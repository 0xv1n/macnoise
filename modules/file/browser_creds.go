package file

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

type fileBrowserCreds struct{}

type browserTarget struct {
	name  string
	paths []string
}

// errNotRegularFile marks a target path that exists but holds nothing to read,
// so it is reported as a probe rather than a denied read.
var errNotRegularFile = errors.New("not a regular file")

// chromiumProfileDirs enumerates the profile directories under base. Chromium
// keeps the first profile in "Default" and any additional ones in "Profile 1",
// "Profile 2", and so on, so assuming a single profile misses every credential
// store belonging to secondary profiles. When none are found "Default" is
// returned so an absent browser still produces a probe event.
func chromiumProfileDirs(base string) []string {
	entries, err := os.ReadDir(base)
	if err != nil {
		return []string{filepath.Join(base, "Default")}
	}

	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if name := e.Name(); name == "Default" || name == "Guest Profile" || strings.HasPrefix(name, "Profile ") {
			dirs = append(dirs, filepath.Join(base, name))
		}
	}
	if len(dirs) == 0 {
		return []string{filepath.Join(base, "Default")}
	}
	return dirs
}

// chromiumCredPaths lists the credential stores across every profile under
// base. Local State is included because it holds the key that decrypts Login
// Data, making it part of the set a real stealer collects. Cookies moved into
// a Network subdirectory in newer Chromium releases, so both locations are
// listed and whichever is absent simply reports as a probe.
func chromiumCredPaths(base string) []string {
	paths := []string{filepath.Join(base, "Local State")}
	for _, profile := range chromiumProfileDirs(base) {
		paths = append(paths,
			filepath.Join(profile, "Login Data"),
			filepath.Join(profile, "Cookies"),
			filepath.Join(profile, "Network", "Cookies"),
			filepath.Join(profile, "Web Data"),
		)
	}
	return paths
}

// firefoxCredPaths expands each profile directory into its credential files.
// Firefox names profile directories with a random prefix, so they have to be
// enumerated rather than hardcoded. When no profile exists the profiles
// directory itself is returned, so an absent Firefox still produces a probe
// event instead of silently emitting nothing.
func firefoxCredPaths(home string) []string {
	profilesDir := filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return []string{profilesDir}
	}

	var paths []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		for _, name := range []string{"logins.json", "key4.db", "cookies.sqlite"} {
			paths = append(paths, filepath.Join(profilesDir, e.Name(), name))
		}
	}
	if len(paths) == 0 {
		return []string{profilesDir}
	}
	return paths
}

// readCredFile opens path and reads it to completion, returning the bytes read.
// The contents are discarded rather than retained: the goal is to generate the
// open and read telemetry a real credential stealer would, not to collect
// anything.
func readCredFile(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() {
		return 0, errNotRegularFile
	}
	return io.Copy(io.Discard, f)
}

func (f *fileBrowserCreds) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_browser_creds",
		EventTypes:  []string{"browser_cred_probe", "browser_cred_read"},
		Description: "Reads known browser credential files to generate browser credential access telemetry",
		Category:    module.CategoryFile,
		Tags:        []string{"browser", "credentials", "chromium", "firefox", "safari"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1555", SubTech: ".003", Name: "Credentials from Password Stores: Credentials from Web Browsers"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (f *fileBrowserCreds) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{
			Name:         "browsers",
			Description:  "Comma-separated browser names to probe, or 'all'",
			Required:     false,
			DefaultValue: "all",
			Example:      "chrome,firefox",
		},
	}
}

func (f *fileBrowserCreds) CheckPrereqs() error { return nil }

func browserTargets() ([]browserTarget, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}
	appSupport := filepath.Join(home, "Library", "Application Support")
	return []browserTarget{
		{name: "chrome", paths: chromiumCredPaths(filepath.Join(appSupport, "Google", "Chrome"))},
		{name: "chromecanary", paths: chromiumCredPaths(filepath.Join(appSupport, "Google", "Chrome Canary"))},
		{name: "brave", paths: chromiumCredPaths(filepath.Join(appSupport, "BraveSoftware", "Brave-Browser"))},
		{name: "edge", paths: chromiumCredPaths(filepath.Join(appSupport, "Microsoft Edge"))},
		{name: "arc", paths: chromiumCredPaths(filepath.Join(appSupport, "Arc", "User Data"))},
		{name: "vivaldi", paths: chromiumCredPaths(filepath.Join(appSupport, "Vivaldi"))},
		{name: "opera", paths: chromiumCredPaths(filepath.Join(appSupport, "com.operasoftware.Opera"))},
		{name: "operagx", paths: chromiumCredPaths(filepath.Join(appSupport, "com.operasoftware.OperaGX"))},
		{name: "yandex", paths: chromiumCredPaths(filepath.Join(appSupport, "Yandex", "YandexBrowser"))},
		{name: "firefox", paths: firefoxCredPaths(home)},
		{
			name: "safari",
			paths: []string{
				filepath.Join(home, "Library", "Cookies", "Cookies.binarycookies"),
			},
		},
	}, nil
}

func (f *fileBrowserCreds) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	browsersParam := params.Get("browsers", "all")
	info := f.Info()

	targets, err := browserTargets()
	if err != nil {
		return err
	}

	filter := map[string]bool{}
	if browsersParam != "all" {
		for _, b := range strings.Split(browsersParam, ",") {
			filter[strings.TrimSpace(strings.ToLower(b))] = true
		}
	}

	for _, browser := range targets {
		if len(filter) > 0 && !filter[browser.name] {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		for _, path := range browser.paths {
			n, readErr := readCredFile(path)

			var ev module.TelemetryEvent
			switch {
			case os.IsNotExist(readErr) || errors.Is(readErr, errNotRegularFile):
				ev = output.NewEvent(info, "browser_cred_probe", true,
					fmt.Sprintf("%s credential path not present: %s", browser.name, path))
				// An absent path means no read was attempted and no access
				// decision was made, the same distinction the TCC probes draw.
				ev = output.WithOutcome(ev, module.OutcomeIndeterminate, nil)
				ev = output.WithDetails(ev, map[string]any{
					"browser": browser.name,
					"path":    path,
					"exists":  false,
				})

			case readErr != nil:
				// The file exists but could not be opened, which on macOS
				// usually means TCC denied it. That refusal is the signal a
				// detection is meant to see, so it is reported as a completed
				// read attempt rather than a module failure.
				ev = output.NewEvent(info, "browser_cred_read", true,
					fmt.Sprintf("%s credential file read denied: %s", browser.name, path))
				ev = output.WithOutcome(ev, module.OutcomeDenied, readErr)
				ev = output.WithDetails(ev, map[string]any{
					"browser":    browser.name,
					"path":       path,
					"exists":     true,
					"accessible": false,
				})

			default:
				ev = output.NewEvent(info, "browser_cred_read", true,
					fmt.Sprintf("%s credential file read: %s (%d bytes)", browser.name, path, n))
				ev = output.WithDetails(ev, map[string]any{
					"browser":    browser.name,
					"path":       path,
					"exists":     true,
					"accessible": true,
					"bytes_read": n,
				})
			}
			emit(ev)
		}
	}
	return nil
}

func (f *fileBrowserCreds) DryRun(params module.Params) []string {
	browsersParam := params.Get("browsers", "all")
	return []string{
		fmt.Sprintf("open and read browser credential files for: %s (contents discarded)", browsersParam),
	}
}

func (f *fileBrowserCreds) Cleanup() error { return nil }

func init() {
	module.Register(&fileBrowserCreds{})
}
