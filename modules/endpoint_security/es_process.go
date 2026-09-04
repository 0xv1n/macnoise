package endpointsecurity

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type esProcess struct{}

func (e *esProcess) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "es_process",
		EventTypes:  []string{"es_exec_chain"},
		Description: "Executes process chains that trigger ES_EVENT_TYPE_NOTIFY_EXEC/FORK/EXIT",
		Category:    module.CategoryEndpointSecurity,
		Tags:        []string{"endpoint-security", "process", "exec", "fork"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1059", SubTech: ".004", Name: "Command and Scripting Interpreter: Unix Shell"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.15",
	}
}

func (e *esProcess) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "chain_depth", Description: "Number of nested shell invocations", Required: false, DefaultValue: "3", Example: "5"},
	}
}

func (e *esProcess) CheckPrereqs() error { return nil }

// buildExecChainArgs nests depth-1 levels of `sh -c '"$@"' sh <rest>` around
// a final `echo es_exit`. The '"$@"' script just re-execs its own
// positional params, so nesting threads through argv with no shell-quote
// escaping needed. The run ID rides on the leaf echo argument so it lands in
// the ES_EVENT_TYPE_NOTIFY_EXEC argv a consumer captures.
func buildExecChainArgs(depth int, runID string) []string {
	leaf := "es_exit"
	if runID != "" {
		leaf = "es_exit_" + runID
	}
	args := []string{"echo", leaf}
	for i := 0; i < depth-1; i++ {
		wrapped := make([]string, 0, len(args)+4)
		wrapped = append(wrapped, "sh", "-c", `"$@"`, "sh")
		wrapped = append(wrapped, args...)
		args = wrapped
	}
	return args
}

func (e *esProcess) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	depthStr := params.Get("chain_depth", "3")
	depth := 3
	fmt.Sscanf(depthStr, "%d", &depth) //nolint:errcheck
	if depth > 10 {
		depth = 10
	}

	info := e.Info()

	ev := output.NewEvent(info, "es_exec_chain", false,
		fmt.Sprintf("executing %d-deep process fork/exec chain", depth))

	chainArgs := buildExecChainArgs(depth, module.RunIDFromContext(ctx))
	cmd := exec.CommandContext(ctx, chainArgs[0], chainArgs[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}
	ev.Success = true
	ev.Message = fmt.Sprintf("%d-deep exec chain completed (ES_EVENT_TYPE_NOTIFY_EXEC/FORK/EXIT)", depth)
	ev = output.WithDetails(ev, map[string]any{
		"chain_depth": depth,
		"output":      string(out),
		"es_events":   []string{"ES_EVENT_TYPE_NOTIFY_EXEC", "ES_EVENT_TYPE_NOTIFY_FORK", "ES_EVENT_TYPE_NOTIFY_EXIT"},
	})
	emit(ev)
	return nil
}

func (e *esProcess) DryRun(params module.Params) []string {
	depth := params.Get("chain_depth", "3")
	return []string{
		fmt.Sprintf("execute %s-deep nested sh -c chain → ES_EVENT_TYPE_NOTIFY_EXEC/FORK/EXIT", depth),
	}
}

func (e *esProcess) Cleanup() error { return nil }

func init() {
	module.Register(&esProcess{})
}
