// Package endpointsecurity provides telemetry modules that trigger Endpoint Security
// framework event types. Modules perform concrete file and process operations so that
// ES_EVENT_TYPE_NOTIFY_* events are visible to any ES client monitoring the system.
package endpointsecurity

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
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
		Description: "Performs file operations that trigger ES_EVENT_TYPE_NOTIFY_CREATE/OPEN/WRITE/SETMODE/RENAME/UNLINK",
		Category:    module.CategoryEndpointSecurity,
		Tags:        []string{"endpoint-security", "file", "create", "open", "write", "setmode", "rename", "delete"},
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

	// Opening for read is a distinct ES event from the write below, which opens
	// for append. NOTIFY_OPEN already fires incidentally from the credential
	// modules, but this is the module an operator runs to exercise ES file
	// coverage, so it names the event rather than leaving it implicit.
	openEv := output.NewEvent(info, "es_notify_open", false, fmt.Sprintf("opening %s (triggers ES_EVENT_TYPE_NOTIFY_OPEN)", targetPath))
	if rf, err := os.Open(targetPath); err != nil {
		openEv = output.WithError(openEv, err)
		emit(openEv)
	} else {
		n, _ := io.Copy(io.Discard, rf)
		_ = rf.Close()
		openEv.Success = true
		openEv.Message = fmt.Sprintf("opened %s (ES_EVENT_TYPE_NOTIFY_OPEN)", targetPath)
		openEv = output.WithDetails(openEv, map[string]any{"path": targetPath, "es_event": "ES_EVENT_TYPE_NOTIFY_OPEN", "bytes_read": n})
		emit(openEv)
	}

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

	setmodeEv := output.NewEvent(info, "es_notify_setmode", false, fmt.Sprintf("chmod %s (triggers ES_EVENT_TYPE_NOTIFY_SETMODE)", targetPath))
	if err := os.Chmod(targetPath, 0o600); err != nil {
		setmodeEv = output.WithError(setmodeEv, err)
		emit(setmodeEv)
	} else {
		setmodeEv.Success = true
		setmodeEv.Message = fmt.Sprintf("chmod 0600 on %s (ES_EVENT_TYPE_NOTIFY_SETMODE)", targetPath)
		setmodeEv = output.WithDetails(setmodeEv, map[string]any{"path": targetPath, "es_event": "ES_EVENT_TYPE_NOTIFY_SETMODE", "mode": "0600"})
		emit(setmodeEv)
	}

	// Rename moves the target, so the tracked path has to follow it or an
	// interrupted run would leave the renamed file behind while Cleanup looked
	// for the original name.
	renamedPath := filepath.Join(workDir, "es_notify_rename.txt")
	previousPath := targetPath
	renameEv := output.NewEvent(info, "es_notify_rename", false, fmt.Sprintf("renaming %s (triggers ES_EVENT_TYPE_NOTIFY_RENAME)", targetPath))
	if err := os.Rename(targetPath, renamedPath); err != nil {
		renameEv = output.WithError(renameEv, err)
		emit(renameEv)
	} else {
		targetPath = renamedPath
		e.createdPath = renamedPath
		renameEv.Success = true
		renameEv.Message = fmt.Sprintf("renamed to %s (ES_EVENT_TYPE_NOTIFY_RENAME)", renamedPath)
		renameEv = output.WithDetails(renameEv, map[string]any{"path": renamedPath, "es_event": "ES_EVENT_TYPE_NOTIFY_RENAME", "previous_path": previousPath})
		emit(renameEv)
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
	// path.Join, not filepath.Join: these are always macOS paths, and a
	// Windows-compiled binary would otherwise advertise backslashes in a dry run
	// it can never perform. Same trap es_mount hit.
	target := path.Join(workDir, "es_notify_create.txt")
	renamed := path.Join(workDir, "es_notify_rename.txt")
	return []string{
		fmt.Sprintf("create %s → ES_EVENT_TYPE_NOTIFY_CREATE", target),
		fmt.Sprintf("open and read %s → ES_EVENT_TYPE_NOTIFY_OPEN", target),
		fmt.Sprintf("write to %s → ES_EVENT_TYPE_NOTIFY_WRITE", target),
		fmt.Sprintf("chmod 0600 %s → ES_EVENT_TYPE_NOTIFY_SETMODE", target),
		fmt.Sprintf("rename %s to %s → ES_EVENT_TYPE_NOTIFY_RENAME", target, renamed),
		fmt.Sprintf("delete %s → ES_EVENT_TYPE_NOTIFY_UNLINK", renamed),
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
