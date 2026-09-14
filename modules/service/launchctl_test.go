package service

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

// launchctl load/unload are the legacy subcommands. Detection content keys on
// bootstrap/bootout, so emitting the old form generates activity modern rules
// are not watching for.
func TestBootstrapArgs_UsesModernSubcommand(t *testing.T) {
	got := bootstrapArgs("gui/501", "/Users/x/Library/LaunchAgents/com.example.plist")
	want := []string{"bootstrap", "gui/501", "/Users/x/Library/LaunchAgents/com.example.plist"}

	if len(got) != len(want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if got[0] == "load" {
		t.Error("still using the legacy load subcommand")
	}
}

// bootout takes a service target rather than a plist path, so unloading still
// resolves after the plist has been deleted.
func TestBootoutArgs_TargetsServiceNotPath(t *testing.T) {
	got := bootoutArgs("system", "com.macnoise.testdaemon")
	want := []string{"bootout", "system/com.macnoise.testdaemon"}

	if len(got) != len(want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if strings.HasSuffix(got[len(got)-1], ".plist") {
		t.Error("bootout target should be a service target, not a plist path")
	}
}

// A LaunchAgent is registered per user, so the domain target must carry the
// uid. Daemons use the single system domain instead.
func TestGuiDomain_CarriesUID(t *testing.T) {
	got := guiDomain(os.Getuid())
	want := fmt.Sprintf("gui/%d", os.Getuid())
	if got != want {
		t.Errorf("guiDomain() = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, "gui/") {
		t.Errorf("guiDomain() = %q, want a gui/<uid> domain target", got)
	}
}

func TestSelectLaunchdUser(t *testing.T) {
	tests := []struct {
		name    string
		process launchdUser
		console launchdUser
		want    launchdUser
		wantErr bool
	}{
		{
			name:    "unprivileged process owns its scope",
			process: launchdUser{uid: 503, home: "/Users/macnoise"},
			console: launchdUser{uid: 501, home: "/Users/console"},
			want:    launchdUser{uid: 503, home: "/Users/macnoise"},
		},
		{
			name:    "root targets logged-in console user",
			process: launchdUser{uid: 0, home: "/var/root"},
			console: launchdUser{uid: 501, home: "/Users/console"},
			want:    launchdUser{uid: 501, home: "/Users/console"},
		},
		{
			name:    "root without GUI user is rejected",
			process: launchdUser{uid: 0, home: "/var/root"},
			console: launchdUser{uid: 0, home: "/var/root"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectLaunchdUser(tt.process, tt.console)
			if (err != nil) != tt.wantErr {
				t.Fatalf("selectLaunchdUser() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("selectLaunchdUser() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSystemDomain(t *testing.T) {
	if systemDomain != "system" {
		t.Errorf("systemDomain = %q, want system", systemDomain)
	}
}

func TestDryRun_AdvertisesBootstrap(t *testing.T) {
	tests := []struct {
		name string
		gen  module.Generator
	}{
		{"launch_agent", &svcLaunchAgent{}},
		{"launch_daemon", &svcLaunchDaemon{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			joined := strings.Join(tt.gen.DryRun(module.Params{}), "\n")
			if !strings.Contains(joined, "launchctl bootstrap") {
				t.Errorf("dry-run does not mention launchctl bootstrap:\n%s", joined)
			}
			if strings.Contains(joined, "launchctl load") {
				t.Errorf("dry-run still advertises the legacy load subcommand:\n%s", joined)
			}
		})
	}
}

// Cleanup must not run bootout when Generate never loaded the service. A host
// without a GUI session fails to bootstrap, and treating the resulting bootout
// failure as a cleanup error would mark those runs failed while nothing was
// actually left behind.
func TestCleanup_SkipsBootoutWhenNeverLoaded(t *testing.T) {
	if err := (&svcLaunchAgent{label: "com.macnoise.never", loaded: false}).Cleanup(context.Background()); err != nil {
		t.Errorf("agent Cleanup() = %v, want nil when the agent was never loaded", err)
	}
	if err := (&svcLaunchDaemon{label: "com.macnoise.never", loaded: false}).Cleanup(context.Background()); err != nil {
		t.Errorf("daemon Cleanup() = %v, want nil when the daemon was never loaded", err)
	}
}
