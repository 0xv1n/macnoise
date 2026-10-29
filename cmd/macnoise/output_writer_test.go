package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestMetadataCommandsHonorConfiguredOutput(t *testing.T) {
	format := globalFormat
	globalFormat = "human"
	t.Cleanup(func() { globalFormat = format })

	commands := []struct {
		name string
		cmd  *cobra.Command
		args []string
	}{
		{name: "list", cmd: buildList()},
		{name: "info", cmd: buildInfo(), args: []string{"file_find"}},
		{name: "categories", cmd: buildCategories()},
		{name: "version", cmd: buildVersion()},
	}
	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			root := &cobra.Command{Use: "root"}
			root.AddCommand(tc.cmd)
			var outputs [2]bytes.Buffer
			for i := range outputs {
				root.SetOut(&outputs[i])
				root.SetArgs(append([]string{tc.name}, tc.args...))
				if err := root.Execute(); err != nil {
					t.Fatal(err)
				}
				if outputs[i].Len() == 0 {
					t.Fatalf("execution %d wrote nothing to its configured output", i+1)
				}
			}
			if outputs[0].String() != outputs[1].String() {
				t.Fatalf("output changed across executions: first=%q second=%q", outputs[0].String(), outputs[1].String())
			}
		})
	}
}

func TestRunEventsUseConfiguredOutputAndFile(t *testing.T) {
	format, outputPath, runID := globalFormat, globalOutput, globalRunID
	dryRun, noCleanup := globalDryRun, globalNoCleanup
	globalFormat = "jsonl"
	globalOutput = filepath.Join(t.TempDir(), "events.jsonl")
	globalRunID = "output-writer-test"
	globalDryRun = false
	globalNoCleanup = false
	t.Cleanup(func() {
		globalFormat = format
		globalOutput = outputPath
		globalRunID = runID
		globalDryRun = dryRun
		globalNoCleanup = noCleanup
	})

	cmd := buildRun()
	if err := cmd.Flags().Set("param", "base_dir="+t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("param", "filename=output-writer-test.txt"); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd.SetOut(&output)
	if err := cmd.RunE(cmd, []string{"file_create"}); err != nil {
		t.Fatal(err)
	}

	stdout := output.String()
	file, err := os.ReadFile(globalOutput)
	if err != nil {
		t.Fatal(err)
	}
	if stdout == "" || string(file) != stdout {
		t.Fatalf("stdout and --output differ: stdout=%q file=%q", stdout, file)
	}
	if !strings.Contains(stdout, `"event_type":"file_create"`) {
		t.Fatalf("captured output has no file creation event: %s", stdout)
	}
}
