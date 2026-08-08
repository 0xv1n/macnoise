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
	ev := output.NewEvent(info, "tcc_contacts_probe", true, fmt.Sprintf("enumerating %s", abPath))
	details := map[string]any{"path": abPath}

	entries, err := os.ReadDir(abPath)
	outcome := classifyProbe(err)
	details["result"] = string(outcome)

	switch outcome {
	case probeGranted:
		ev.Message = fmt.Sprintf("Contacts TCC probe: read access granted, found %d entries in %s", len(entries), abPath)
		details["entry_count"] = len(entries)
	case probeDenied:
		ev.Message = fmt.Sprintf("Contacts TCC probe: access denied to %s (expected without permission)", abPath)
	case probeAbsent:
		ev.Message = fmt.Sprintf("Contacts TCC probe: %s does not exist, no TCC decision was made", abPath)
	default:
		ev.Message = fmt.Sprintf("Contacts TCC probe: unexpected failure reading %s", abPath)
	}

	ev = output.WithOutcome(ev, eventOutcome(outcome), err)
	ev = output.WithDetails(ev, details)
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
