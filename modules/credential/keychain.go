// Package credential provides native credential-store operations.
package credential

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/internal/subprocess"
	"github.com/0xv1n/macnoise/pkg/module"
)

type credKeychain struct{}

const maxKeychainPaths = 100

func (c *credKeychain) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "cred_keychain",
		EventTypes:  []string{"keychain_list", "keychain_unlock_attempt", "keychain_dump_attempt"},
		Description: "Lists configured keychains, then attempts to unlock and dump one concrete keychain",
		Category:    module.CategoryCredential,
		Tags:        []string{"credentials", "keychain", "security"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1555", SubTech: ".001", Name: "Credentials from Password Stores: Keychain"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (c *credKeychain) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:        "keychain_path",
			Description: "Literal keychain path (defaults to the configured user keychain)",
			Type:        module.ParamPath,
			Example:     "/Users/victim/Library/Keychains/login.keychain-db",
		},
		{
			Name:        "password",
			Description: "Password for the unlock attempt (empty commonly produces denial telemetry)",
			Type:        module.ParamString,
			Sensitive:   true,
			Default:     "",
			Example:     "hunter2",
		},
	}
}

func (c *credKeychain) CheckPrereqs(ctx context.Context, params module.Params) error {
	return prereqs.CheckCommand("security")
}

func parseKeychainPaths(out []byte) []string {
	lines := strings.Split(string(out), "\n")
	paths := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if unquoted, err := strconv.Unquote(line); err == nil {
			line = unquoted
		}
		if line != "" {
			paths = append(paths, line)
			if len(paths) == maxKeychainPaths {
				break
			}
		}
	}
	return paths
}

func keychainCommandOutcome(err error, combinedOutput string) module.Outcome {
	if err == nil {
		return module.OutcomeExecuted
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return module.OutcomeError
	}
	text := strings.ToLower(combinedOutput)
	switch {
	case strings.Contains(text, "could not be found"),
		strings.Contains(text, "does not exist"),
		strings.Contains(text, "no such file"):
		return module.OutcomeIndeterminate
	case strings.Contains(text, "passphrase"),
		strings.Contains(text, "password"),
		strings.Contains(text, "interaction is not allowed"),
		strings.Contains(text, "authorization denied"),
		strings.Contains(text, "user canceled"):
		return module.OutcomeDenied
	default:
		return module.OutcomeError
	}
}

func resolveKeychainPath(ctx context.Context, explicit string, listed []string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	result, err := subprocess.Run(ctx, "security", "default-keychain", "-d", "user")
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err == nil {
		if paths := parseKeychainPaths(result.Output); len(paths) > 0 {
			return paths[0], nil
		}
	} else if keychainCommandOutcome(err, string(result.Output)) == module.OutcomeError {
		return "", fmt.Errorf("security default-keychain: %w: %s", err, strings.TrimSpace(string(result.Output)))
	}
	for _, path := range listed {
		if _, statErr := os.Stat(path); statErr == nil {
			return path, nil
		}
	}
	if len(listed) > 0 {
		return listed[0], nil
	}
	return "", nil
}

func keychainObservation(info module.ModuleInfo, eventType, action, path string, outcome module.Outcome, err error, commandOutput string) module.TelemetryEvent {
	name := "configured keychain"
	if path == "" {
		name = "no configured keychain"
	}
	ev := output.NewEvent(info, eventType, outcome, module.Resource("keychain", name, path), fmt.Sprintf("%s %s", action, path))
	details := map[string]any{"path": path, "result": string(outcome)}
	if commandOutput != "" && outcome != module.OutcomeExecuted {
		details["output"] = commandOutput
	}
	if err != nil {
		ev = output.WithOutcome(ev, outcome, err)
	}
	switch outcome {
	case module.OutcomeExecuted:
		ev.Message = fmt.Sprintf("keychain %s succeeded for %s", action, path)
	case module.OutcomeDenied:
		ev.Message = fmt.Sprintf("keychain %s denied for %s", action, path)
	case module.OutcomeIndeterminate:
		ev.Message = fmt.Sprintf("keychain %s was not attempted because the target is absent", action)
	default:
		ev.Message = fmt.Sprintf("keychain %s failed unexpectedly for %s", action, path)
	}
	return output.WithDetails(ev, details)
}

func (c *credKeychain) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info := c.Info()

	listResult, listErr := subprocess.Run(ctx, "security", "list-keychains", "-d", "user")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	listPaths := parseKeychainPaths(listResult.Output)
	listOutcome := keychainCommandOutcome(listErr, string(listResult.Output))
	listEv := output.NewEvent(info, "keychain_list", listOutcome, module.Resource("keychain", "user search list", ""), "listing configured user keychains")
	listEv = output.WithDetails(listEv, map[string]any{"paths": listPaths, "count": len(listPaths)})
	if listErr != nil {
		listEv = output.WithOutcome(listEv, listOutcome, fmt.Errorf("security list-keychains: %w: %s", listErr, strings.TrimSpace(string(listResult.Output))))
	}
	if err := emit(listEv); err != nil {
		return err
	}
	if listOutcome == module.OutcomeError {
		return fmt.Errorf("security list-keychains: %w", listErr)
	}

	keychainPath, err := resolveKeychainPath(ctx, params.String("keychain_path", ""), listPaths)
	if err != nil {
		return err
	}
	if keychainPath == "" {
		for _, spec := range []struct{ eventType, action string }{
			{"keychain_unlock_attempt", "unlock"},
			{"keychain_dump_attempt", "dump"},
		} {
			if emitErr := emit(keychainObservation(info, spec.eventType, spec.action, "", module.OutcomeIndeterminate, nil, "")); emitErr != nil {
				return emitErr
			}
		}
		return nil
	}
	if _, statErr := os.Stat(keychainPath); statErr != nil {
		if os.IsNotExist(statErr) {
			for _, spec := range []struct{ eventType, action string }{
				{"keychain_unlock_attempt", "unlock"},
				{"keychain_dump_attempt", "dump"},
			} {
				if emitErr := emit(keychainObservation(info, spec.eventType, spec.action, keychainPath, module.OutcomeIndeterminate, nil, "")); emitErr != nil {
					return emitErr
				}
			}
			return nil
		}
		return fmt.Errorf("inspect keychain %s: %w", keychainPath, statErr)
	}

	password := params.String("password", "")
	commands := []struct {
		eventType string
		action    string
		args      []string
	}{
		{"keychain_unlock_attempt", "unlock", []string{"unlock-keychain", "-p", password, keychainPath}},
		{"keychain_dump_attempt", "dump", []string{"dump-keychain", keychainPath}},
	}
	for _, command := range commands {
		result, runErr := subprocess.Run(ctx, "security", command.args...)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		commandOutput := strings.TrimSpace(string(result.Output))
		outcome := keychainCommandOutcome(runErr, commandOutput)
		var observationErr error
		if runErr != nil {
			observationErr = fmt.Errorf("security %s-keychain: %w: %s", command.action, runErr, commandOutput)
		}
		if err := emit(keychainObservation(info, command.eventType, command.action, keychainPath, outcome, observationErr, commandOutput)); err != nil {
			return err
		}
		if outcome == module.OutcomeError {
			return observationErr
		}
	}
	return nil
}

func (c *credKeychain) DryRun(params module.Params) []string {
	keychainPath := params.String("keychain_path", "<configured user keychain>")
	return []string{
		"security list-keychains -d user",
		fmt.Sprintf("security unlock-keychain -p %s %s", module.RedactedValue, keychainPath),
		fmt.Sprintf("security dump-keychain %s", keychainPath),
	}
}

func (c *credKeychain) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &credKeychain{} })
}
