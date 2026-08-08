// Package audit provides OCSF 1.7.0-aligned structured audit logging for MacNoise runs.
// Each record captures what MacNoise itself did — which module ran, timing,
// prereq and cleanup outcomes, MITRE techniques exercised, and events emitted —
// as opposed to the telemetry events that modules generate for EDR consumption.
package audit

// Record is a single OCSF 1.7.0-aligned audit log entry written to the audit JSONL file.
type Record struct {
	ActivityID   int    `json:"activity_id"`
	ActivityName string `json:"activity_name,omitempty"`
	CategoryUID  int    `json:"category_uid"`
	CategoryName string `json:"category_name,omitempty"`
	ClassUID     int    `json:"class_uid"`
	ClassName    string `json:"class_name,omitempty"`
	SeverityID   int    `json:"severity_id"`
	Severity     string `json:"severity,omitempty"`
	Time         int64  `json:"time"`
	TypeUID      int    `json:"type_uid"`
	TypeName     string `json:"type_name,omitempty"`
	Message      string `json:"message,omitempty"`
	// StatusID carries no omitempty because OCSF status_id 0 is Unknown, a
	// meaningful value for an indeterminate outcome rather than an absent one.
	StatusID  int          `json:"status_id"`
	Status    string       `json:"status,omitempty"`
	StartTime int64        `json:"start_time,omitempty"`
	EndTime   int64        `json:"end_time,omitempty"`
	Duration  int64        `json:"duration,omitempty"`
	Metadata  OCSFMetadata `json:"metadata"`
	Actor     *OCSFActor   `json:"actor,omitempty"`
	Device    *OCSFDevice  `json:"device,omitempty"`
	File      *OCSFFile    `json:"file,omitempty"`
	Process   *OCSFProcess `json:"process,omitempty"`
	Attacks   []OCSFAttack `json:"attacks,omitempty"`
	Unmapped  any          `json:"unmapped,omitempty"`
}

// OCSFDevice identifies the host macnoise is running on. Required by OCSF for
// file_activity (1001) and process_activity (1007); populated once per
// Logger and reused across every record rather than recomputed per event.
type OCSFDevice struct {
	TypeID   int    `json:"type_id"`
	Hostname string `json:"hostname,omitempty"`
}

// OCSFFile identifies the file targeted by a file_activity (1001) record.
// Required by OCSF for that class.
type OCSFFile struct {
	Name   string `json:"name"`
	Path   string `json:"path,omitempty"`
	TypeID int    `json:"type_id"`
}

// OCSFMetadata carries OCSF product and log metadata embedded in every Record.
type OCSFMetadata struct {
	Version        string      `json:"version"`
	Product        OCSFProduct `json:"product"`
	LogName        string      `json:"log_name"`
	CorrelationUID string      `json:"correlation_uid,omitempty"`
}

// OCSFProduct identifies the tool that generated the audit record.
type OCSFProduct struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	VendorName string `json:"vendor_name"`
}

// OCSFActor represents the process that performed the audited action.
type OCSFActor struct {
	Process *OCSFProcess `json:"process,omitempty"`
}

// OCSFProcess holds process-level details for the OCSF actor.
type OCSFProcess struct {
	PID     int       `json:"pid,omitempty"`
	Name    string    `json:"name,omitempty"`
	CmdLine string    `json:"cmd_line,omitempty"`
	User    *OCSFUser `json:"user,omitempty"`
}

// OCSFUser holds user identity fields for an OCSF process.
type OCSFUser struct {
	Name string `json:"name,omitempty"`
}

// OCSFAttack maps a Record to a MITRE ATT&CK technique and optional sub-technique.
type OCSFAttack struct {
	Technique    OCSFTechnique     `json:"technique"`
	SubTechnique *OCSFSubTechnique `json:"sub_technique,omitempty"`
	Tactic       *OCSFTactic       `json:"tactic,omitempty"`
}

// OCSFTechnique holds the UID and name of a MITRE ATT&CK technique.
type OCSFTechnique struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
}

// OCSFSubTechnique holds the UID and name of a MITRE ATT&CK sub-technique.
type OCSFSubTechnique struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
}

// OCSFTactic holds the UID and name of a MITRE ATT&CK tactic.
type OCSFTactic struct {
	UID  string `json:"uid,omitempty"`
	Name string `json:"name,omitempty"`
}

// UnmappedData holds macnoise-specific fields that have no direct OCSF mapping.
type UnmappedData struct {
	Module         string            `json:"module"`
	ModuleCategory string            `json:"module_category"`
	Params         map[string]string `json:"params,omitempty"`
	Privileges     string            `json:"privileges"`
	// Outcome preserves the four-way event outcome that OCSF status collapses:
	// status cannot tell a refused action apart from a broken tool, since both
	// are a Failure of the reported activity.
	Outcome       string `json:"outcome,omitempty"`
	DryRun        bool   `json:"dry_run"`
	PrereqResult  string `json:"prereq_result,omitempty"`
	PrereqError   string `json:"prereq_error,omitempty"`
	EventsEmitted int    `json:"events_emitted,omitempty"`
	CleanupResult string `json:"cleanup_result,omitempty"`
	CleanupError  string `json:"cleanup_error,omitempty"`
	ScenarioName  string `json:"scenario_name,omitempty"`
	ScenarioFile  string `json:"scenario_file,omitempty"`
}

// ScenarioUnmappedData holds scenario-level fields for Records written by LogScenario.
type ScenarioUnmappedData struct {
	ScenarioName  string `json:"scenario_name"`
	ScenarioFile  string `json:"scenario_file"`
	StepsPassed   int    `json:"steps_passed"`
	StepsFailed   int    `json:"steps_failed"`
	TotalSteps    int    `json:"total_steps"`
	ScenarioError string `json:"scenario_error,omitempty"`
}
