package audit

import "testing"

// One row per event type actually emitted by a module (re-derived with
// grep -rhoP 'NewEvent\(info,\s*"\K[a-z_0-9]+' modules/ | sort -u, plus
// plist_create/plist_create_launchagent which build their event type via a
// variable rather than a literal and so don't show up in that grep).
func TestClassify(t *testing.T) {
	tests := []struct {
		category     string
		eventType    string
		wantClassUID int
		wantActID    int
	}{
		// network
		{"network", "dns_lookup", 4003, 1},
		{"network", "http_get", 4002, 3},
		{"network", "http_beacon", 4002, 3},
		{"network", "http_post_exfil", 4002, 6},
		{"network", "tcp_connect", 4001, 1},
		{"network", "tcp_accept", 4001, 1},
		{"network", "tcp_listen", 4001, 7},
		{"network", "reverse_shell_attempt", 4001, 1},

		// file
		{"file", "archive_create", 1001, 1},
		{"file", "browser_cred_probe", 1001, 8},
		{"file", "browser_cred_read", 1001, 2},
		{"file", "dir_create", 1001, 1},
		{"file", "file_create", 1001, 1},
		{"file", "file_hide_chflags", 1001, 6},
		{"file", "file_hide_dotfile", 1001, 1},
		{"file", "file_modify", 1001, 3},

		// plist (routed through the file/plist case)
		{"plist", "plist_modify", 1001, 3},
		{"plist", "plist_read_prior", 1001, 2},
		{"plist", "plist_create", 1001, 1},
		{"plist", "plist_create_launchagent", 1001, 1},

		// process
		{"process", "dylib_inject_attempt", 1007, 4},
		{"process", "osascript_exec", 1007, 1},
		{"process", "process_fork", 1007, 1},
		{"process", "process_spawn", 1007, 1},
		{"process", "signal_send", 1007, 99},
		{"process", "spctl_status_check", 1007, 1},
		{"process", "system_discovery", 1007, 1},
		{"process", "test_file_create_fail", 1007, 99},
		{"process", "xattr_quarantine_remove", 1007, 1},
		{"process", "xattr_quarantine_set", 1007, 1},

		// service
		{"service", "cron_job_create", 1006, 1},
		{"service", "cron_job_list", 1006, 99},
		{"service", "launchagent_create", 1006, 1},
		{"service", "launchagent_load", 1006, 6},
		{"service", "launchdaemon_create", 1006, 1},
		{"service", "launchdaemon_load", 1006, 6},
		{"service", "login_item_add", 1006, 1},
		{"service", "shell_profile_modify", 1006, 2},

		// tcc / xpc
		{"tcc", "keychain_dump_attempt", 6003, 2},
		{"tcc", "keychain_list", 6003, 2},
		{"tcc", "keychain_unlock_attempt", 6003, 3},
		{"tcc", "tcc_accessibility_probe", 6003, 2},
		{"tcc", "tcc_contacts_probe", 6003, 2},
		{"tcc", "tcc_fda_probe", 6003, 2},
		{"tcc", "screen_capture_attempt", 6003, 2},
		{"xpc", "xpc_enumerate", 6003, 2},

		// endpoint_security
		{"endpoint_security", "es_exec_chain", 1007, 1},
		{"endpoint_security", "es_notify_create", 1001, 1},
		{"endpoint_security", "es_notify_write", 1001, 3},
		{"endpoint_security", "es_notify_unlink", 1001, 4},
		{"endpoint_security", "es_dmg_create", 1001, 1},
		{"endpoint_security", "es_notify_mount", 1001, 12},
		{"endpoint_security", "es_notify_unmount", 1001, 13},
		{"endpoint_security", "es_volume_exec", 1007, 1},

		// unmapped category/event falls back to API Activity/Other
		{"unknown_category", "unknown_event", 6003, 99},
	}

	for _, tt := range tests {
		t.Run(tt.category+"/"+tt.eventType, func(t *testing.T) {
			cl := Classify(tt.category, tt.eventType)
			if cl.ClassUID != tt.wantClassUID {
				t.Errorf("ClassUID = %d, want %d", cl.ClassUID, tt.wantClassUID)
			}
			if cl.ActivityID != tt.wantActID {
				t.Errorf("ActivityID = %d, want %d", cl.ActivityID, tt.wantActID)
			}
		})
	}
}

func TestClassify_TypeUIDConsistency(t *testing.T) {
	cl := Classify("network", "tcp_connect")
	typeUID := cl.ClassUID*100 + cl.ActivityID
	if typeUID != 400101 {
		t.Errorf("type_uid = %d, want 400101", typeUID)
	}
}
