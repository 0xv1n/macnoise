package file

import (
	"context"
	"fmt"
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

func chromiumCredPaths(profileBase string) []string {
	return []string{
		filepath.Join(profileBase, "Default", "Login Data"),
		filepath.Join(profileBase, "Default", "Cookies"),
		filepath.Join(profileBase, "Default", "Web Data"),
	}
}

func (f *fileBrowserCreds) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "file_browser_creds",
		Description: "Probes known browser credential file paths via stat to generate browser credential access telemetry",
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
		{name: "brave", paths: chromiumCredPaths(filepath.Join(appSupport, "BraveSoftware", "Brave-Browser"))},
		{name: "edge", paths: chromiumCredPaths(filepath.Join(appSupport, "Microsoft Edge"))},
		{name: "arc", paths: chromiumCredPaths(filepath.Join(appSupport, "Arc", "User Data"))},
		{name: "vivaldi", paths: chromiumCredPaths(filepath.Join(appSupport, "Vivaldi"))},
		{name: "opera", paths: chromiumCredPaths(filepath.Join(appSupport, "com.operasoftware.Opera"))},
		{name: "operagx", paths: chromiumCredPaths(filepath.Join(appSupport, "com.operasoftware.OperaGX"))},
		{
			name: "firefox",
			paths: []string{
				filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles"),
			},
		},
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
			ev := output.NewEvent(info, "browser_cred_probe", false, fmt.Sprintf("probing %s: %s", browser.name, path))
			fi, statErr := os.Stat(path)
			if statErr != nil {
				ev.Success = true
				ev.Message = fmt.Sprintf("%s credential path not accessible: %s", browser.name, path)
				ev = output.WithDetails(ev, map[string]any{
					"browser": browser.name,
					"path":    path,
					"exists":  false,
				})
			} else {
				ev.Success = true
				ev.Message = fmt.Sprintf("%s credential file found: %s (%d bytes)", browser.name, path, fi.Size())
				ev = output.WithDetails(ev, map[string]any{
					"browser":  browser.name,
					"path":     path,
					"exists":   true,
					"size":     fi.Size(),
					"modified": fi.ModTime().UTC().Format("2006-01-02T15:04:05Z"),
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
		fmt.Sprintf("stat browser credential paths for: %s", browsersParam),
	}
}

func (f *fileBrowserCreds) Cleanup() error { return nil }

func init() {
	module.Register(&fileBrowserCreds{})
}
