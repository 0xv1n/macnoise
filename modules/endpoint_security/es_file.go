// Package endpointsecurity provides telemetry modules that trigger Endpoint Security
// framework event types. Modules perform concrete file and process operations so that
// ES_EVENT_TYPE_NOTIFY_* events are visible to any ES client monitoring the system.
package endpointsecurity

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type esFile struct {
	createdPath string
}

func (e *esFile) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "es_file",
		Description: "Performs file operations that trigger ES_EVENT_TYPE_NOTIFY_CREATE/WRITE/UNLINK",
		Category:    module.CategoryEndpointSecurity,
		Tags:        []string{"endpoint-security", "file", "create", "write", "delete"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1074", SubTech: ".001", Name: "Data Staged: Local Data Staging"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.15",
	}
}

func (e *esFile) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "work_dir", Description: "Directory for ES file operations", Required: false, DefaultValue: "/tmp/macnoise_es", Example: "/var/tmp/es_test"},
	}
}

func (e *esFile) CheckPrereqs() error { return nil }

func (e *esFile) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	workDir := params.Get("work_dir", "/tmp/macnoise_es")
	info := e.Info()

	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", workDir, err)
	}

	targetPath := filepath.Join(workDir, "es_notify_create.txt")
	e.createdPath = targetPath

	createEv := output.NewEvent(info, "es_notify_create", false, fmt.Sprintf("creating %s (triggers ES_EVENT_TYPE_NOTIFY_CREATE)", targetPath))
	if err := os.WriteFile(targetPath, []byte("es_create\n"), 0o644); err != nil {
		createEv = output.WithError(createEv, err)
		emit(createEv)
		return err
	}
	createEv.Success = true
	createEv.Message = fmt.Sprintf("created %s (ES_EVENT_TYPE_NOTIFY_CREATE)", targetPath)
	createEv = output.WithDetails(createEv, map[string]any{"path": targetPath, "es_event": "ES_EVENT_TYPE_NOTIFY_CREATE"})
	emit(createEv)

	writeEv := output.NewEvent(info, "es_notify_write", false, fmt.Sprintf("writing %s (triggers ES_EVENT_TYPE_NOTIFY_WRITE)", targetPath))
	f, err := os.OpenFile(targetPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		writeEv = output.WithError(writeEv, err)
		emit(writeEv)
	} else {
		f.WriteString("es_write\n") //nolint:errcheck
		_ = f.Close()
		writeEv.Success = true
		writeEv.Message = fmt.Sprintf("wrote to %s (ES_EVENT_TYPE_NOTIFY_WRITE)", targetPath)
		writeEv = output.WithDetails(writeEv, map[string]any{"path": targetPath, "es_event": "ES_EVENT_TYPE_NOTIFY_WRITE"})
		emit(writeEv)
	}

	unlinkEv := output.NewEvent(info, "es_notify_unlink", false, fmt.Sprintf("deleting %s (triggers ES_EVENT_TYPE_NOTIFY_UNLINK)", targetPath))
	if err := os.Remove(targetPath); err != nil {
		unlinkEv = output.WithError(unlinkEv, err)
		emit(unlinkEv)
	} else {
		e.createdPath = ""
		unlinkEv.Success = true
		unlinkEv.Message = fmt.Sprintf("deleted %s (ES_EVENT_TYPE_NOTIFY_UNLINK)", targetPath)
		unlinkEv = output.WithDetails(unlinkEv, map[string]any{"path": targetPath, "es_event": "ES_EVENT_TYPE_NOTIFY_UNLINK"})
		emit(unlinkEv)
	}

	return nil
}

func (e *esFile) DryRun(params module.Params) []string {
	workDir := params.Get("work_dir", "/tmp/macnoise_es")
	path := filepath.Join(workDir, "es_notify_create.txt")
	return []string{
		fmt.Sprintf("create %s → ES_EVENT_TYPE_NOTIFY_CREATE", path),
		fmt.Sprintf("write to %s → ES_EVENT_TYPE_NOTIFY_WRITE", path),
		fmt.Sprintf("delete %s → ES_EVENT_TYPE_NOTIFY_UNLINK", path),
	}
}

func (e *esFile) Cleanup() error {
	if e.createdPath != "" {
		return os.Remove(e.createdPath)
	}
	return nil
}

func init() {
	module.Register(&esFile{})
}
