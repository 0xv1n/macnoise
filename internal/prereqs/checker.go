// Package prereqs provides helpers for validating runtime prerequisites
// such as OS type, privilege level, and command availability. Modules call
// these from their CheckPrereqs implementations.
package prereqs

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// IsMacOS reports whether the current OS is macOS (darwin).
func IsMacOS() bool {
	return runtime.GOOS == "darwin"
}

// IsRoot reports whether the process is running as UID 0.
func IsRoot() bool {
	return os.Getuid() == 0
}

// IsAdmin reports whether the current user belongs to the macOS "admin" group.
func IsAdmin() bool {
	out, err := exec.Command("id", "-Gn").Output()
	if err != nil {
		return false
	}
	for _, g := range splitFields(string(out)) {
		if g == "admin" {
			return true
		}
	}
	return false
}

// HasCommand reports whether name can be resolved to an executable via PATH.
func HasCommand(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// CheckMacOS returns an error if the current OS is not macOS.
func CheckMacOS() error {
	if !IsMacOS() {
		return fmt.Errorf("this module requires macOS (darwin); current OS: %s", runtime.GOOS)
	}
	return nil
}

// CheckRoot returns an error if the process is not running as root.
func CheckRoot() error {
	if !IsRoot() {
		return fmt.Errorf("this module requires root privileges (re-run with sudo)")
	}
	return nil
}

// CheckCommand returns an error if name is not found in PATH.
func CheckCommand(name string) error {
	if !HasCommand(name) {
		return fmt.Errorf("required command %q not found in PATH", name)
	}
	return nil
}

func splitFields(s string) []string {
	var fields []string
	cur := ""
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if cur != "" {
				fields = append(fields, cur)
				cur = ""
			}
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		fields = append(fields, cur)
	}
	return fields
}
