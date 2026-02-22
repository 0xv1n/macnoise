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
			Name:         "keychain_path",
			Description:  "Path to the target keychain file (default: ~/Library/Keychains/login.keychain-db)",
			Required:     false,
			DefaultValue: "",
			Example:      "/Users/victim/Library/Keychains/login.keychain-db",
		},
		{
			Name:         "password",
			Description:  "Password for unlock attempt (empty causes expected failure telemetry)",
			Required:     false,
			DefaultValue: "",
			Example:      "hunter2",
		},
	}
}

func (t *tccKeychain) CheckPrereqs() error { return nil }

func (t *tccKeychain) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	keychainPath := params.Get("keychain_path", "")
	password := params.Get("password", "")
	info := t.Info()

	if keychainPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		keychainPath = filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	}

	listEv := output.NewEvent(info, "keychain_list", false, "listing keychains via security list-keychains")
	listOut, listErr := exec.CommandContext(ctx, "security", "list-keychains").CombinedOutput()
	if listErr != nil {
		listEv = output.WithError(listEv, listErr)
	} else {
		listEv.Success = true
		listEv.Message = "keychain list retrieved"
		listEv = output.WithDetails(listEv, map[string]any{"keychains": string(listOut)})
	}
	emit(listEv)

	unlockEv := output.NewEvent(info, "keychain_unlock_attempt", false, fmt.Sprintf("attempting keychain unlock: %s", keychainPath))
	unlockOut, unlockErr := exec.CommandContext(ctx, "security", "unlock-keychain", "-p", password, keychainPath).CombinedOutput()
	if unlockErr != nil {
		unlockEv.Success = true
		unlockEv.Message = fmt.Sprintf("keychain unlock denied for %s (expected without valid password)", keychainPath)
		unlockEv = output.WithDetails(unlockEv, map[string]any{
			"path":   keychainPath,
			"result": "denied",
			"output": string(unlockOut),
		})
	} else {
		unlockEv.Success = true
		unlockEv.Message = fmt.Sprintf("keychain unlocked: %s", keychainPath)
		unlockEv = output.WithDetails(unlockEv, map[string]any{"path": keychainPath, "result": "granted"})
	}
	emit(unlockEv)

	dumpEv := output.NewEvent(info, "keychain_dump_attempt", false, fmt.Sprintf("probing keychain dump: %s", keychainPath))
	dumpOut, dumpErr := exec.CommandContext(ctx, "security", "dump-keychain", keychainPath).CombinedOutput()
	if dumpErr != nil {
		dumpEv.Success = true
		dumpEv.Message = fmt.Sprintf("keychain dump denied for %s (telemetry generated)", keychainPath)
		dumpEv = output.WithDetails(dumpEv, map[string]any{
			"path":   keychainPath,
			"result": "denied",
			"output": string(dumpOut),
		})
	} else {
		dumpEv.Success = true
		dumpEv.Message = fmt.Sprintf("keychain dump succeeded for %s", keychainPath)
		dumpEv = output.WithDetails(dumpEv, map[string]any{"path": keychainPath, "result": "granted"})
	}
	emit(dumpEv)

	return nil
}

func (t *tccKeychain) DryRun(params module.Params) []string {
	keychainPath := params.Get("keychain_path", "~/Library/Keychains/login.keychain-db")
	return []string{
		"security list-keychains",
		fmt.Sprintf("security unlock-keychain -p '' %s", keychainPath),
		fmt.Sprintf("security dump-keychain %s", keychainPath),
	}
}

func (t *tccKeychain) Cleanup() error { return nil }

func init() {
	module.Register(&tccKeychain{})
}
