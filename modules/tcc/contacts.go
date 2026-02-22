package tcc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type tccContacts struct{}

func (t *tccContacts) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "tcc_contacts",
		Description: "Attempts to enumerate the AddressBook directory to probe Contacts TCC permission",
		Category:    module.CategoryTCC,
		Tags:        []string{"tcc", "contacts", "addressbook", "privacy"},
		Privileges:  module.PrivilegeTCC,
		MITRE: []module.MITRE{
			{Technique: "T1636", SubTech: ".003", Name: "Protected User Data: Contact List"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.15",
	}
}

func (t *tccContacts) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "addressbook_path",
			Description:  "Path to AddressBook directory",
			Required:     false,
			DefaultValue: "",
			Example:      "~/Library/Application Support/AddressBook",
		},
	}
}

func (t *tccContacts) CheckPrereqs() error { return nil }

func (t *tccContacts) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	abPath := params.Get("addressbook_path", "")
	if abPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("cannot determine home directory: %w", err)
		}
		abPath = filepath.Join(home, "Library", "Application Support", "AddressBook")
	}

	info := t.Info()
	ev := output.NewEvent(info, "tcc_contacts_probe", false, fmt.Sprintf("enumerating %s", abPath))

	entries, err := os.ReadDir(abPath)
	if err != nil {
		ev.Success = true
		ev.Message = fmt.Sprintf("Contacts TCC probe: access denied to %s (expected without permission)", abPath)
		ev = output.WithDetails(ev, map[string]any{
			"path":   abPath,
			"result": "denied",
		})
		if !os.IsPermission(err) && !os.IsNotExist(err) {
			ev = output.WithError(ev, err)
		}
		emit(ev)
		return nil
	}

	ev.Success = true
	ev.Message = fmt.Sprintf("Contacts TCC probe: read access granted, found %d entries in %s", len(entries), abPath)
	ev = output.WithDetails(ev, map[string]any{
		"path":        abPath,
		"result":      "granted",
		"entry_count": len(entries),
	})
	emit(ev)
	return nil
}

func (t *tccContacts) DryRun(params module.Params) []string {
	return []string{"enumerate ~/Library/Application Support/AddressBook (probes Contacts TCC permission)"}
}

func (t *tccContacts) Cleanup() error { return nil }

func init() {
	module.Register(&tccContacts{})
}
