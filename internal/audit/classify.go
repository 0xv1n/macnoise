package audit

import "github.com/0xv1n/macnoise/pkg/module"

// OutcomeStatus holds the OCSF severity and status identifiers implied by an
// event outcome.
type OutcomeStatus struct {
	SeverityID int
	Severity   string
	StatusID   int
	Status     string
}

// statusForOutcome maps an event outcome to OCSF severity and status.
//
// OCSF status describes the activity being reported rather than macnoise's own
// health, so a denied read is a failed read: denied and error both map to
// Failure. Their distinction is preserved in unmapped.outcome, where a consumer
// that needs it can read it without OCSF semantics having to bend.
//
// Severity is where the two do diverge. Only a genuine macnoise fault is
// elevated; a refused probe is the expected result this tool exists to produce,
// and raising its severity would bury real faults under routine denials.
func statusForOutcome(o module.Outcome) OutcomeStatus {
	switch o {
	case module.OutcomeDenied:
		return OutcomeStatus{1, "Informational", 2, "Failure"}
	case module.OutcomeIndeterminate:
		return OutcomeStatus{1, "Informational", 0, "Unknown"}
	case module.OutcomeError:
		return OutcomeStatus{3, "Medium", 2, "Failure"}
	default:
		return OutcomeStatus{1, "Informational", 1, "Success"}
	}
}

// Classification holds the OCSF class, category, and activity identifiers for an event.
type Classification struct {
	ClassUID     int
	ClassName    string
	CategoryUID  int
	CategoryName string
	ActivityID   int
	ActivityName string
}

// Classify maps a macnoise category and event type to its OCSF Classification.
func Classify(category, eventType string) Classification {
	switch eventType {
	case "http_get", "http_beacon":
		return Classification{4002, "HTTP Activity", 4, "Network Activity", 3, "Get"}
	case "http_post_exfil":
		return Classification{4002, "HTTP Activity", 4, "Network Activity", 6, "Post"}
	case "dns_lookup":
		return Classification{4003, "DNS Activity", 4, "Network Activity", 1, "Query"}
	}

	switch category {
	case "network":
		actID, actName := networkActivity(eventType)
		return Classification{4001, "Network Activity", 4, "Network Activity", actID, actName}

	case "process":
		actID, actName := processActivity(eventType)
		return Classification{1007, "Process Activity", 1, "System Activity", actID, actName}

	case "file", "plist":
		actID, actName := fileActivity(eventType)
		return Classification{1001, "File System Activity", 1, "System Activity", actID, actName}

	case "tcc", "xpc":
		actID, actName := apiActivity(eventType)
		return Classification{6003, "API Activity", 6, "Application Activity", actID, actName}

	case "endpoint_security":
		return endpointSecurityActivity(eventType)

	case "service":
		actID, actName := serviceActivity(eventType)
		return Classification{1006, "Scheduled Job Activity", 1, "System Activity", actID, actName}
	}

	return Classification{6003, "API Activity", 6, "Application Activity", 99, "Other"}
}

func networkActivity(eventType string) (int, string) {
	switch eventType {
	case "tcp_listen":
		return 7, "Listen"
	case "tcp_connect", "tcp_accept", "reverse_shell_attempt":
		return 1, "Open"
	}
	return 99, "Other"
}

func processActivity(eventType string) (int, string) {
	switch eventType {
	case "process_spawn", "process_fork", "osascript_exec", "system_discovery",
		"xattr_quarantine_set", "xattr_quarantine_remove", "spctl_status_check":
		return 1, "Launch"
	case "dylib_inject_attempt":
		return 4, "Inject"
	}
	return 99, "Other"
}

func fileActivity(eventType string) (int, string) {
	switch eventType {
	case "file_create", "dir_create", "file_hide_dotfile", "archive_create",
		"plist_create", "plist_create_launchagent", "keychain_copy":
		return 1, "Create"
	case "plist_read_prior", "browser_cred_read", "cred_file_read", "keychain_read":
		return 2, "Read"
	case "file_modify", "plist_modify":
		return 3, "Update"
	case "file_hide_chflags":
		return 6, "Set Attributes"
	case "browser_cred_probe", "cred_file_probe":
		return 8, "Get Attributes"
	}
	return 99, "Other"
}

func serviceActivity(eventType string) (int, string) {
	switch eventType {
	case "cron_job_create", "launchagent_create", "launchdaemon_create", "login_item_add":
		return 1, "Create"
	case "shell_profile_modify":
		return 2, "Update"
	case "launchagent_load", "launchdaemon_load":
		return 6, "Start"
	}
	return 99, "Other"
}

func apiActivity(eventType string) (int, string) {
	switch eventType {
	case "keychain_list", "keychain_dump_attempt", "tcc_contacts_probe",
		"tcc_fda_probe", "tcc_accessibility_probe", "screen_capture_attempt", "xpc_enumerate":
		return 2, "Read"
	case "keychain_unlock_attempt":
		return 3, "Update"
	}
	return 99, "Other"
}

func endpointSecurityActivity(eventType string) Classification {
	switch eventType {
	case "es_notify_create":
		return Classification{1001, "File System Activity", 1, "System Activity", 1, "Create"}
	case "es_notify_write":
		return Classification{1001, "File System Activity", 1, "System Activity", 3, "Update"}
	case "es_notify_unlink":
		return Classification{1001, "File System Activity", 1, "System Activity", 4, "Delete"}
	case "es_dmg_create":
		return Classification{1001, "File System Activity", 1, "System Activity", 1, "Create"}
	case "es_notify_mount":
		return Classification{1001, "File System Activity", 1, "System Activity", 12, "Mount"}
	case "es_notify_unmount":
		return Classification{1001, "File System Activity", 1, "System Activity", 13, "Unmount"}
	case "es_exec_chain", "es_volume_exec":
		return Classification{1007, "Process Activity", 1, "System Activity", 1, "Launch"}
	}
	return Classification{6003, "API Activity", 6, "Application Activity", 99, "Other"}
}
