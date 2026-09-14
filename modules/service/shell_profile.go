package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

const (
	shellProfileMarkerStart = "# macnoise-marker-start"
	shellProfileMarkerEnd   = "# macnoise-marker-end"
)

type svcShellProfile struct {
	targetFile string
	block      string
	mode       os.FileMode
	created    bool
}

func (s *svcShellProfile) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "svc_shell_profile",
		EventTypes:  []string{"shell_profile_modify"},
		Description: "Appends a marked payload block to a shell profile file to simulate shell persistence",
		Category:    module.CategoryService,
		Tags:        []string{"shell-profile", "persistence", "zshrc", "bashrc"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1546", SubTech: ".004", Name: "Event Triggered Execution: Unix Shell Configuration Modification"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (s *svcShellProfile) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "target", Description: "Shell profile file to modify", Type: module.ParamPath, Default: "~/.zshrc", Example: "~/.bash_profile"},
		{Name: "payload", Description: "Shell expression to inject between markers", Type: module.ParamString, Default: "export MACNOISE_PERSIST=1", Example: "alias ls='ls -la'"},
	}
}

func (s *svcShellProfile) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

func (s *svcShellProfile) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	target := params.String("target", "~/.zshrc")
	payload := params.String("payload", "export MACNOISE_PERSIST=1")
	info := s.Info()

	if strings.HasPrefix(target, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		target = filepath.Join(home, target[2:])
	}
	s.targetFile = target
	infoBefore, statErr := os.Stat(target)
	s.created = os.IsNotExist(statErr)
	if statErr != nil && !s.created {
		return fmt.Errorf("stat %s: %w", target, statErr)
	}
	s.mode = 0o644
	if infoBefore != nil {
		s.mode = infoBefore.Mode().Perm()
	}

	// The run ID rides on the start marker line (Cleanup still matches on the
	// constant prefix) so a consumer can correlate the profile change.
	startMarker := shellProfileMarkerStart
	if runID := module.RunIDFromContext(ctx); runID != "" {
		startMarker += " mn:" + runID
	}
	block := fmt.Sprintf("\n%s\n%s\n%s\n", startMarker, payload, shellProfileMarkerEnd)

	ev := output.NewEvent(info, "shell_profile_modify", module.OutcomeError, module.File(target), fmt.Sprintf("appending persistence marker to %s", target))
	f, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		ev = output.WithError(ev, err)
		return errors.Join(err, emit(ev))
	}
	written, writeErr := f.WriteString(block)
	if writeErr == nil && written != len(block) {
		writeErr = io.ErrShortWrite
	}
	closeErr := f.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		ev = output.WithError(ev, writeErr)
		return errors.Join(writeErr, emit(ev))
	}
	s.block = block

	ev.Outcome = module.OutcomeExecuted
	ev.Message = fmt.Sprintf("persistence marker block appended to %s", target)
	ev = output.WithDetails(ev, map[string]any{
		"target":  target,
		"payload": payload,
		"block":   block,
	})
	return emit(ev)
}

func (s *svcShellProfile) DryRun(params module.Params) []string {
	target := params.String("target", "~/.zshrc")
	payload := params.String("payload", "export MACNOISE_PERSIST=1")
	return []string{
		fmt.Sprintf("append %s/%s/%s block to %s", shellProfileMarkerStart, payload, shellProfileMarkerEnd, target),
	}
}

func (s *svcShellProfile) Cleanup(ctx context.Context) error {
	if s.targetFile == "" || s.block == "" {
		return nil
	}
	data, err := os.ReadFile(s.targetFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("svc_shell_profile cleanup %s: owned marker target is missing", s.targetFile)
		}
		return err
	}
	content, err := removeOwnedBlock(string(data), s.block)
	if err != nil {
		return fmt.Errorf("svc_shell_profile cleanup %s: %w", s.targetFile, err)
	}
	if s.created && content == "" {
		err = os.Remove(s.targetFile)
	} else {
		err = os.WriteFile(s.targetFile, []byte(content), s.mode)
	}
	if err == nil {
		s.targetFile = ""
		s.block = ""
	}
	return err
}

func removeOwnedBlock(content, block string) (string, error) {
	switch count := strings.Count(content, block); count {
	case 1:
		return strings.Replace(content, block, "", 1), nil
	case 0:
		return "", fmt.Errorf("owned marker block was removed or modified")
	default:
		return "", fmt.Errorf("owned marker block occurs %d times", count)
	}
}

func init() {
	module.Register(func() module.Generator { return &svcShellProfile{} })
}
