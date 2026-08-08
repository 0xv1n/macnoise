package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xv1n/macnoise/pkg/module"
)

// LifecycleData carries timing and outcome fields recorded for each module execution lifecycle event.
type LifecycleData struct {
	StartTime     time.Time
	EndTime       time.Time
	PrereqResult  string
	PrereqError   string
	GenerateError string
	EventsEmitted int
	CleanupResult string
	CleanupError  string
	DryRun        bool
	ScenarioName  string
	ScenarioFile  string
	StepsPassed   int
	StepsFailed   int
	TotalSteps    int
}

// Logger writes OCSF-aligned JSONL audit records to a file, safe for concurrent use.
type Logger struct {
	mu      sync.Mutex
	f       *os.File
	runID   string
	version string
	actor   *OCSFActor
	device  *OCSFDevice
}

// NewLogger opens (or creates) path for append and returns a ready Logger.
func NewLogger(path, version string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return &Logger{
		f:       f,
		runID:   generateRunID(),
		version: version,
		actor:   currentActor(),
		device:  currentDevice(),
	}, nil
}

// Close flushes and closes the underlying audit log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		err := l.f.Close()
		l.f = nil
		return err
	}
	return nil
}

// WrapEmitter returns an EventEmitter that forwards events to emit and also logs each one via LogEvent.
func (l *Logger) WrapEmitter(emit module.EventEmitter, info module.ModuleInfo, params module.Params, count *int) module.EventEmitter {
	return func(ev module.TelemetryEvent) {
		emit(ev)
		*count++
		l.LogEvent(ev, info, params)
	}
}

// LogEvent writes an OCSF audit record for a single telemetry event emitted by a module.
func (l *Logger) LogEvent(ev module.TelemetryEvent, info module.ModuleInfo, params module.Params) {
	cl := Classify(ev.Category, ev.EventType)
	now := epochMS(time.Now())

	outcome := ev.ResolvedOutcome()
	st := statusForOutcome(outcome)

	rec := Record{
		ActivityID:   cl.ActivityID,
		ActivityName: cl.ActivityName,
		CategoryUID:  cl.CategoryUID,
		CategoryName: cl.CategoryName,
		ClassUID:     cl.ClassUID,
		ClassName:    cl.ClassName,
		SeverityID:   st.SeverityID,
		Severity:     st.Severity,
		Time:         now,
		TypeUID:      cl.ClassUID*100 + cl.ActivityID,
		TypeName:     fmt.Sprintf("%s: %s", cl.ClassName, cl.ActivityName),
		Message:      ev.Message,
		StatusID:     st.StatusID,
		Status:       st.Status,
		Metadata:     l.metadata(),
		Actor:        l.actor,
		Device:       l.device,
		Attacks:      mitreToAttacks(info.MITRE),
		Unmapped: UnmappedData{
			Module:         info.Name,
			ModuleCategory: string(info.Category),
			Params:         map[string]string(params),
			Privileges:     string(info.Privileges),
			Outcome:        string(outcome),
		},
	}

	switch cl.ClassUID {
	case 1001:
		rec.File = extractFile(ev.EventType, ev.Details)
	case 1007:
		rec.Process = extractProcess(ev.Details, l.actor.Process)
	}

	l.write(rec)
}

// LogLifecycle writes an OCSF audit record for a module lifecycle event (prereq, run, dry-run, cleanup).
func (l *Logger) LogLifecycle(recordType string, info module.ModuleInfo, params module.Params, data LifecycleData) {
	now := epochMS(time.Now())

	severityID, severity := lifecycleSeverity(data)
	statusID, status := lifecycleStatus(data)
	message := lifecycleMessage(recordType, info.Name, data)

	var startMS, endMS, dur int64
	if !data.StartTime.IsZero() {
		startMS = epochMS(data.StartTime)
	}
	if !data.EndTime.IsZero() {
		endMS = epochMS(data.EndTime)
	}
	if startMS > 0 && endMS > 0 {
		dur = endMS - startMS
	}

	unmapped := UnmappedData{
		Module:         info.Name,
		ModuleCategory: string(info.Category),
		Params:         map[string]string(params),
		Privileges:     string(info.Privileges),
		DryRun:         data.DryRun,
		PrereqResult:   data.PrereqResult,
		PrereqError:    data.PrereqError,
		EventsEmitted:  data.EventsEmitted,
		CleanupResult:  data.CleanupResult,
		CleanupError:   data.CleanupError,
		ScenarioName:   data.ScenarioName,
		ScenarioFile:   data.ScenarioFile,
	}

	rec := Record{
		ActivityID:   99,
		ActivityName: "Other",
		CategoryUID:  6,
		CategoryName: "Application Activity",
		ClassUID:     6003,
		ClassName:    "API Activity",
		SeverityID:   severityID,
		Severity:     severity,
		Time:         now,
		TypeUID:      6003*100 + 99,
		TypeName:     "API Activity: Other",
		Message:      message,
		StatusID:     statusID,
		Status:       status,
		StartTime:    startMS,
		EndTime:      endMS,
		Duration:     dur,
		Metadata:     l.metadata(),
		Actor:        l.actor,
		Device:       l.device,
		Attacks:      mitreToAttacks(info.MITRE),
		Unmapped:     unmapped,
	}

	l.write(rec)
}

// LogScenario writes an OCSF audit record summarising the outcome of a full scenario run.
func (l *Logger) LogScenario(name, path string, data LifecycleData) {
	now := epochMS(time.Now())

	severityID := 1
	severity := "Informational"
	statusID := 1
	status := "Success"
	if data.StepsFailed > 0 || data.GenerateError != "" {
		severityID = 3
		severity = "Medium"
		statusID = 2
		status = "Failure"
	}

	var startMS, endMS, dur int64
	if !data.StartTime.IsZero() {
		startMS = epochMS(data.StartTime)
	}
	if !data.EndTime.IsZero() {
		endMS = epochMS(data.EndTime)
	}
	if startMS > 0 && endMS > 0 {
		dur = endMS - startMS
	}

	msg := fmt.Sprintf("Scenario %q: %d/%d steps passed", name, data.StepsPassed, data.TotalSteps)
	if data.GenerateError != "" {
		msg += ": " + data.GenerateError
	}

	rec := Record{
		ActivityID:   99,
		ActivityName: "Other",
		CategoryUID:  6,
		CategoryName: "Application Activity",
		ClassUID:     6003,
		ClassName:    "API Activity",
		SeverityID:   severityID,
		Severity:     severity,
		Time:         now,
		TypeUID:      6003*100 + 99,
		TypeName:     "API Activity: Other",
		Message:      msg,
		StatusID:     statusID,
		Status:       status,
		StartTime:    startMS,
		EndTime:      endMS,
		Duration:     dur,
		Metadata:     l.metadata(),
		Actor:        l.actor,
		Device:       l.device,
		Unmapped: ScenarioUnmappedData{
			ScenarioName:  name,
			ScenarioFile:  path,
			StepsPassed:   data.StepsPassed,
			StepsFailed:   data.StepsFailed,
			TotalSteps:    data.TotalSteps,
			ScenarioError: data.GenerateError,
		},
	}

	l.write(rec)
}

func (l *Logger) write(rec Record) {
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return
	}
	l.f.Write(b)            //nolint:errcheck
	l.f.Write([]byte{'\n'}) //nolint:errcheck
}

func (l *Logger) metadata() OCSFMetadata {
	return OCSFMetadata{
		Version: "1.7.0",
		Product: OCSFProduct{
			Name:       "MacNoise",
			Version:    l.version,
			VendorName: "0xv1n",
		},
		LogName:        "audit",
		CorrelationUID: l.runID,
	}
}

func epochMS(t time.Time) int64 {
	return t.UnixNano() / int64(time.Millisecond)
}

func currentActor() *OCSFActor {
	// cmd_line is declared by OCSF and was never populated. It is what an
	// analyst needs to tell one macnoise run from another in a shared log.
	proc := &OCSFProcess{
		PID:     os.Getpid(),
		Name:    "MacNoise",
		CmdLine: strings.Join(os.Args, " "),
	}
	if u, err := user.Current(); err == nil {
		proc.User = &OCSFUser{Name: u.Username}
	}
	return &OCSFActor{Process: proc}
}

// currentDevice identifies the local host. type_id is Unknown (0) rather
// than a guess at Desktop/Laptop, since nothing here can reliably tell them
// apart; hostname alone satisfies OCSF's "at least one identifying field" rule.
func currentDevice() *OCSFDevice {
	hostname, _ := os.Hostname()
	return &OCSFDevice{TypeID: 0, Hostname: hostname}
}

// extractFile builds the file object a file_activity (1001) record requires
// from whatever the emitting module put in ev.Details. Modules aren't
// required to use a consistent key for this (most use "path"; file_archive
// uses "output_path" for the archive it created), so this is deliberately
// best-effort: if no known key is present, it still returns a non-nil File
// (satisfying the required field) generic enough not to claim data that
// isn't there.
func extractFile(eventType string, details map[string]any) *OCSFFile {
	path, _ := details["path"].(string)
	if path == "" {
		path, _ = details["output_path"].(string)
	}
	typeID := 1 // Regular File
	if eventType == "dir_create" {
		typeID = 2 // Folder
	}
	if path == "" {
		return &OCSFFile{Name: eventType, TypeID: typeID}
	}
	return &OCSFFile{Name: filepath.Base(path), Path: path, TypeID: typeID}
}

// extractProcess builds the process object a process_activity (1007) record
// requires. A handful of modules record the actual target process's pid
// and/or command in ev.Details (process_fork has both; process_spawn and
// dylib_inject_attempt have a command/target with no pid, since those exec
// synchronously rather than tracking a forked pid); everything else falls
// back to macnoise's own process, since it performed the activity even when
// it didn't hand off to a distinctly-tracked child.
func extractProcess(details map[string]any, fallback *OCSFProcess) *OCSFProcess {
	name, hasName := details["command"].(string)
	if !hasName {
		name, hasName = details["target"].(string)
	}
	pid, hasPID := details["pid"].(int)

	if !hasName && !hasPID {
		return fallback
	}
	proc := &OCSFProcess{Name: name}
	if hasPID {
		proc.PID = pid
	}
	return proc
}

func mitreToAttacks(mitre []module.MITRE) []OCSFAttack {
	if len(mitre) == 0 {
		return nil
	}
	attacks := make([]OCSFAttack, 0, len(mitre))
	for _, m := range mitre {
		attack := OCSFAttack{
			Technique: OCSFTechnique{
				UID:  m.Technique,
				Name: techniqueName(m.Name),
			},
		}
		if m.SubTech != "" {
			attack.SubTechnique = &OCSFSubTechnique{
				UID:  m.Technique + m.SubTech,
				Name: subTechniqueName(m.Name),
			}
		}
		attacks = append(attacks, attack)
	}
	return attacks
}

func techniqueName(name string) string {
	if i := strings.Index(name, ": "); i >= 0 {
		return name[:i]
	}
	return name
}

func subTechniqueName(name string) string {
	if i := strings.Index(name, ": "); i >= 0 {
		return name[i+2:]
	}
	return ""
}

func lifecycleSeverity(data LifecycleData) (int, string) {
	if data.PrereqResult == "fail" {
		return 2, "Low"
	}
	if data.GenerateError != "" {
		return 3, "Medium"
	}
	return 1, "Informational"
}

func lifecycleStatus(data LifecycleData) (int, string) {
	if data.PrereqResult == "fail" || data.GenerateError != "" {
		return 2, "Failure"
	}
	return 1, "Success"
}

func lifecycleMessage(recordType, moduleName string, data LifecycleData) string {
	switch recordType {
	case "module_prereq_fail":
		return fmt.Sprintf("Module %s prereq check failed: %s", moduleName, data.PrereqError)
	case "module_dry_run":
		return fmt.Sprintf("Module %s dry-run completed", moduleName)
	default:
		if data.GenerateError != "" {
			return fmt.Sprintf("Module %s failed: %s", moduleName, data.GenerateError)
		}
		return fmt.Sprintf("Module %s completed successfully (%d events emitted)", moduleName, data.EventsEmitted)
	}
}
