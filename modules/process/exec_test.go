package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestProcExecGenerate_PreservesArgumentsAndPublishesOutputs(t *testing.T) {
	ctx, outputs := execOutputContext()
	var events []module.TelemetryEvent
	params := helperExecParams(0, "literal ; $(not-a-shell)")
	if err := (&procExec{}).Generate(ctx, params, captureExecEvents(&events)); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if len(events) != 1 || events[0].Outcome != module.OutcomeExecuted {
		t.Fatalf("events = %+v, want one executed event", events)
	}
	if outputs["output"] != "literal ; $(not-a-shell)" || outputs["exit_code"] != 0 {
		t.Fatalf("outputs = %+v", outputs)
	}
	argv, ok := events[0].Details["argv"].([]string)
	if !ok || argv[len(argv)-1] != "literal ; $(not-a-shell)" {
		t.Fatalf("argv details = %#v", events[0].Details["argv"])
	}
}

func TestProcExecGenerate_NonzeroPolicy(t *testing.T) {
	for _, tt := range []struct {
		name          string
		acceptNonzero bool
		wantErr       bool
	}{
		{name: "error", wantErr: true},
		{name: "accepted", acceptNonzero: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, outputs := execOutputContext()
			var events []module.TelemetryEvent
			params := helperExecParams(9, "failed")
			params["accept_nonzero"] = tt.acceptNonzero
			err := (&procExec{}).Generate(ctx, params, captureExecEvents(&events))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Generate = %v, wantErr %v", err, tt.wantErr)
			}
			if outputs["exit_code"] != 9 || len(events) != 1 {
				t.Fatalf("outputs = %+v; events = %+v", outputs, events)
			}
			wantOutcome := module.OutcomeError
			if tt.acceptNonzero {
				wantOutcome = module.OutcomeExecuted
			}
			if events[0].Outcome != wantOutcome {
				t.Fatalf("outcome = %s, want %s", events[0].Outcome, wantOutcome)
			}
		})
	}
}

func TestProcExecGenerate_CanceledBeforeExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var events []module.TelemetryEvent
	err := (&procExec{}).Generate(ctx, helperExecParams(0, "ignored"), captureExecEvents(&events))
	if !errors.Is(err, context.Canceled) || len(events) != 0 {
		t.Fatalf("Generate = %v, events = %+v; want cancellation without event", err, events)
	}
}

func TestProcExecContract(t *testing.T) {
	p := &procExec{}
	specs := p.ParamSpecs()
	if specs[0].Default != "/usr/bin/true" || !specs[1].Sensitive || specs[2].Name != "working_dir" || specs[2].Type != module.ParamPath {
		t.Fatalf("parameter specs = %+v", specs)
	}
	outputs := p.OutputSpecs()
	if len(outputs) != 2 || !outputs[0].Sensitive || outputs[1].Type != module.ParamInteger {
		t.Fatalf("output specs = %+v", outputs)
	}
}

func TestProcExecGenerateReportsSelectedExecutablePath(t *testing.T) {
	helperExecutable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("PATH", dir)
	data, err := os.ReadFile(helperExecutable)
	if err != nil {
		t.Fatal(err)
	}
	helperPath := "helper" + filepath.Ext(helperExecutable)
	if err := os.WriteFile(filepath.Join(dir, helperPath), data, 0o755); err != nil {
		t.Fatal(err)
	}
	workingDir := "work"
	if err := os.Mkdir(workingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, helperPath), data, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name       string
		executable string
		workingDir string
		wantPath   string
	}{
		{name: "PATH without working directory", executable: helperPath, wantPath: filepath.Join(dir, helperPath)},
		{name: "PATH with working directory", executable: helperPath, workingDir: workingDir, wantPath: filepath.Join(dir, helperPath)},
		{name: "relative executable and working directory", executable: "./" + helperPath, workingDir: workingDir, wantPath: filepath.Join(workingDir, helperPath)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, _ := execOutputContext()
			var events []module.TelemetryEvent
			params := helperExecParams(0, "ok")
			params["executable"] = tt.executable
			params["working_dir"] = tt.workingDir
			if err := (&procExec{}).Generate(ctx, params, captureExecEvents(&events)); err != nil {
				t.Fatal(err)
			}
			if len(events) != 1 || (tt.workingDir != "" && events[0].Details["working_directory"] != tt.workingDir) {
				t.Fatalf("events = %+v", events)
			}
			got := events[0].Subject.Process.Executable
			reportedInfo, err := os.Stat(got)
			if err != nil {
				t.Fatal(err)
			}
			wantInfo, err := os.Stat(tt.wantPath)
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(reportedInfo, wantInfo) {
				t.Fatalf("reported executable = %q, want the file at %q", got, tt.wantPath)
			}
		})
	}
}

func TestProcExecGenerateReportsExecutableThroughSymlinkAndDotDot(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	helperExecutable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(helperExecutable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join("other", "subdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join("other", "tool")
	if err := os.WriteFile(target, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("tool", []byte("not an executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("other", "subdir"), "link"); err != nil {
		t.Fatal(err)
	}

	const executable = "./link/../tool"
	ctx, _ := execOutputContext()
	var events []module.TelemetryEvent
	params := helperExecParams(0, "target")
	params["executable"] = executable
	if err := (&procExec{}).Generate(ctx, params, captureExecEvents(&events)); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one process event", events)
	}
	reportedInfo, err := os.Stat(events[0].Subject.Process.Executable)
	if err != nil {
		t.Fatal(err)
	}
	targetInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(reportedInfo, targetInfo) {
		t.Fatalf("reported executable %q does not identify launched target %q", events[0].Subject.Process.Executable, target)
	}
}

func TestProcExecGenerateMissingPATHExecutableKeepsDeclaredTarget(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	const executable = "macnoise-missing-executable"
	ctx, _ := execOutputContext()
	var events []module.TelemetryEvent
	params := helperExecParams(0, "ignored")
	params["executable"] = executable
	params["working_dir"] = t.TempDir()
	if err := (&procExec{}).Generate(ctx, params, captureExecEvents(&events)); err == nil {
		t.Fatal("Generate succeeded for a missing PATH executable")
	}
	if len(events) != 1 || events[0].Subject.Process.Executable != executable {
		t.Fatalf("events = %+v, want declared executable %q", events, executable)
	}
}

func execOutputContext() (context.Context, module.Params) {
	outputs := module.Params{}
	ctx := module.ContextWithOutputSink(context.Background(), func(name string, value any) error {
		outputs[name] = value
		return nil
	})
	return ctx, outputs
}

func helperExecParams(exitCode int, output string) module.Params {
	return module.Params{
		"executable": os.Args[0],
		"args":       []string{"-test.run=TestProcExecHelper", "--", "--macnoise-proc-exec-helper", strconv.Itoa(exitCode), output},
	}
}

func TestProcExecHelper(t *testing.T) {
	index := procExecArgumentIndex("--macnoise-proc-exec-helper")
	if index < 0 || len(os.Args) < index+3 {
		return
	}
	code, err := strconv.Atoi(os.Args[index+1])
	if err != nil {
		panic(err)
	}
	fmt.Print(os.Args[index+2])
	os.Exit(code)
}

func procExecArgumentIndex(want string) int {
	for index, arg := range os.Args {
		if arg == want {
			return index
		}
	}
	return -1
}

func captureExecEvents(events *[]module.TelemetryEvent) module.EventEmitter {
	return func(ev module.TelemetryEvent) error {
		*events = append(*events, ev)
		return nil
	}
}
