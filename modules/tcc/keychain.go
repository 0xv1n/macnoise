package tcc

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type tccKeychain struct{}

func (t *tccKeychain) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "tcc_keychain",
		EventTypes:  []string{"keychain_list", "keychain_unlock_attempt", "keychain_dump_attempt"},
		Description: "Probes keychain access by listing, unlocking, and dumping keychain entries to generate Keychain TCC telemetry",
		Category:    module.CategoryTCC,
		Tags:        []string{"tcc", "keychain", "credentials", "security"},
		Privileges:  module.PrivilegeTCC,
		MITRE: []module.MITRE{
			{Technique: "T1555", SubTech: ".001", Name: "Credentials from Password Stores: Keychain"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (t *tccKeychain) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:        "keychain_path",
			Description: "Path to the target keychain file (default: ~/Library/Keychains/login.keychain-db)",
			Type:        module.ParamPath,
			Example:     "/Users/victim/Library/Keychains/login.keychain-db",
		},
		{
			Name:        "password",
			Description: "Password for unlock attempt (empty causes expected failure telemetry)",
			Type:        module.ParamString,
			Sensitive:   true,
			Default:     "",
			Example:     "hunter2",
		},
	}
}

func (t *tccKeychain) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

func (t *tccKeychain) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	keychainPath := params.String("keychain_path", "")
	password := params.String("password", "")
	info := t.Info()

	if keychainPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		keychainPath = filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	}

	listEv := output.NewEvent(info, "keychain_list", module.OutcomeError, module.Resource("keychain", "configured keychains", keychainPath), "listing keychains via security list-keychains")
	listOut, listErr := exec.CommandContext(ctx, "security", "list-keychains").CombinedOutput()
	if listErr != nil {
		listEv = output.WithError(listEv, listErr)
	} else {
		listEv.Outcome = module.OutcomeExecuted
		listEv.Message = "keychain list retrieved"
		listEv = output.WithDetails(listEv, map[string]any{"keychains": string(listOut)})
	}
	if err := emit(listEv); err != nil {
		return err
	}

	unlockEv := output.NewEvent(info, "keychain_unlock_attempt", module.OutcomeError, module.Resource("keychain", "login keychain", keychainPath), fmt.Sprintf("attempting keychain unlock: %s", keychainPath))
	unlockOut, unlockErr := exec.CommandContext(ctx, "security", "unlock-keychain", "-p", password, keychainPath).CombinedOutput()
	if unlockErr != nil {
		unlockEv = output.WithOutcome(unlockEv, module.OutcomeDenied, nil)
		unlockEv.Message = fmt.Sprintf("keychain unlock denied for %s (expected without valid password)", keychainPath)
		unlockEv = output.WithDetails(unlockEv, map[string]any{
			"path":   keychainPath,
			"result": "denied",
			"output": string(unlockOut),
		})
	} else {
		unlockEv.Outcome = module.OutcomeExecuted
		unlockEv.Message = fmt.Sprintf("keychain unlocked: %s", keychainPath)
		unlockEv = output.WithDetails(unlockEv, map[string]any{"path": keychainPath, "result": "granted"})
	}
	if err := emit(unlockEv); err != nil {
		return err
	}

	dumpEv := output.NewEvent(info, "keychain_dump_attempt", module.OutcomeError, module.Resource("keychain", "login keychain", keychainPath), fmt.Sprintf("probing keychain dump: %s", keychainPath))
	dumpOut, dumpErr := exec.CommandContext(ctx, "security", "dump-keychain", keychainPath).CombinedOutput()
	if dumpErr != nil {
		dumpEv = output.WithOutcome(dumpEv, module.OutcomeDenied, nil)
		dumpEv.Message = fmt.Sprintf("keychain dump denied for %s (telemetry generated)", keychainPath)
		dumpEv = output.WithDetails(dumpEv, map[string]any{
			"path":   keychainPath,
			"result": "denied",
			"output": string(dumpOut),
		})
	} else {
		dumpEv.Outcome = module.OutcomeExecuted
		dumpEv.Message = fmt.Sprintf("keychain dump succeeded for %s", keychainPath)
		dumpEv = output.WithDetails(dumpEv, map[string]any{"path": keychainPath, "result": "granted"})
	}
	return emit(dumpEv)
}

func (t *tccKeychain) DryRun(params module.Params) []string {
	keychainPath := params.String("keychain_path", "~/Library/Keychains/login.keychain-db")
	return []string{
		"security list-keychains",
		fmt.Sprintf("security unlock-keychain -p '' %s", keychainPath),
		fmt.Sprintf("security dump-keychain %s", keychainPath),
	}
}

func (t *tccKeychain) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &tccKeychain{} })
}
