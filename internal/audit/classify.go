package audit

import "strings"

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
	case "http_get", "http_post", "http_put", "http_delete", "http_request", "http_response", "http_connect":
		return Classification{4002, "HTTP Activity", 4, "Network Activity", 1, "Connect"}
	case "dns_query", "dns_lookup", "dns_response", "dns_request":
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
		return Classification{6003, "API Activity", 6, "Application Activity", 99, "Other"}

	case "endpoint_security":
		if strings.Contains(eventType, "file") {
			actID, actName := fileActivity(eventType)
			return Classification{1001, "File System Activity", 1, "System Activity", actID, actName}
		}
		if strings.Contains(eventType, "process") {
			actID, actName := processActivity(eventType)
			return Classification{1007, "Process Activity", 1, "System Activity", actID, actName}
		}
		return Classification{6003, "API Activity", 6, "Application Activity", 99, "Other"}

	case "service":
		return Classification{1006, "Scheduled Job Activity", 1, "System Activity", 1, "Create"}
	}

	return Classification{6003, "API Activity", 6, "Application Activity", 99, "Other"}
}

func networkActivity(eventType string) (int, string) {
	switch eventType {
	case "tcp_listen":
		return 5, "Listen"
	case "beacon", "revshell", "tcp_connect":
		return 1, "Connect"
	}
	return 1, "Connect"
}

func processActivity(eventType string) (int, string) {
	switch eventType {
	case "spawn", "exec", "launch":
		return 1, "Launch"
	case "terminate", "kill":
		return 2, "Terminate"
	case "signal", "sigstop", "sigcont", "inject":
		return 99, "Other"
	}
	return 1, "Launch"
}

func fileActivity(eventType string) (int, string) {
	switch eventType {
	case "create", "write":
		return 3, "Create"
	case "read", "open":
		return 4, "Read"
	case "modify", "update", "rename":
		return 5, "Update"
	case "delete", "remove":
		return 6, "Delete"
	}
	return 3, "Create"
}
