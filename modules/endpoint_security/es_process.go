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

func (e *esProcess) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	depthStr := params.Get("chain_depth", "3")
	depth := 3
	fmt.Sscanf(depthStr, "%d", &depth) //nolint:errcheck
	if depth > 10 {
		depth = 10
	}

	info := e.Info()

	inner := "echo es_exit"
	for i := 0; i < depth-1; i++ {
		inner = fmt.Sprintf("sh -c '%s'", inner)
	}

	ev := output.NewEvent(info, "es_exec_chain", false,
		fmt.Sprintf("executing %d-deep process fork/exec chain", depth))

	cmd := exec.CommandContext(ctx, "sh", "-c", inner)
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
