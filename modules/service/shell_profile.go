package service

import (
	"context"
	"fmt"
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
}

func (s *svcShellProfile) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "svc_shell_profile",
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
		{Name: "target", Description: "Shell profile file to modify", Required: false, DefaultValue: "~/.zshrc", Example: "~/.bash_profile"},
		{Name: "payload", Description: "Shell expression to inject between markers", Required: false, DefaultValue: "export MACNOISE_PERSIST=1", Example: "alias ls='ls -la'"},
	}
}

func (s *svcShellProfile) CheckPrereqs() error { return nil }

func (s *svcShellProfile) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	_ = ctx
	target := params.Get("target", "~/.zshrc")
	payload := params.Get("payload", "export MACNOISE_PERSIST=1")
	info := s.Info()

	if strings.HasPrefix(target, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		target = filepath.Join(home, target[2:])
	}
	s.targetFile = target

	block := fmt.Sprintf("\n%s\n%s\n%s\n", shellProfileMarkerStart, payload, shellProfileMarkerEnd)

	ev := output.NewEvent(info, "shell_profile_modify", false, fmt.Sprintf("appending persistence marker to %s", target))
	f, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}
	_, writeErr := f.WriteString(block)
	_ = f.Close()
	if writeErr != nil {
		ev = output.WithError(ev, writeErr)
		emit(ev)
		return writeErr
	}

	ev.Success = true
	ev.Message = fmt.Sprintf("persistence marker block appended to %s", target)
	ev = output.WithDetails(ev, map[string]any{
		"target":  target,
		"payload": payload,
		"block":   block,
	})
	emit(ev)
	return nil
}

func (s *svcShellProfile) DryRun(params module.Params) []string {
	target := params.Get("target", "~/.zshrc")
	payload := params.Get("payload", "export MACNOISE_PERSIST=1")
	return []string{
		fmt.Sprintf("append %s/%s/%s block to %s", shellProfileMarkerStart, payload, shellProfileMarkerEnd, target),
	}
}

func (s *svcShellProfile) Cleanup() error {
	if s.targetFile == "" {
		return nil
	}
	data, err := os.ReadFile(s.targetFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	content := string(data)
	for {
		startIdx := strings.Index(content, shellProfileMarkerStart)
		if startIdx == -1 {
			break
		}
		endIdx := strings.Index(content[startIdx:], shellProfileMarkerEnd)
		if endIdx == -1 {
			content = content[:startIdx]
			break
		}
		endIdx += startIdx + len(shellProfileMarkerEnd)
		if endIdx < len(content) && content[endIdx] == '\n' {
			endIdx++
		}
		if startIdx > 0 && content[startIdx-1] == '\n' {
			startIdx--
		}
		content = content[:startIdx] + content[endIdx:]
	}
	return os.WriteFile(s.targetFile, []byte(content), 0o644)
}

func init() {
	module.Register(&svcShellProfile{})
}
