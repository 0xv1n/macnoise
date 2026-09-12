package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
// runID is the correlation identifier for this invocation; pass an empty
// string to have one generated automatically.
func NewLogger(path, version, runID string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	if runID == "" {
		runID = GenerateRunID()
	}
	return &Logger{
		f:       f,
		runID:   runID,
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
	return func(ev module.TelemetryEvent) error {
		emitErr := emit(ev)
		*count++
		auditErr := l.LogEvent(ev, info, params)
		return errors.Join(emitErr, auditErr)
	}
}

// LogEvent writes an OCSF audit record for a single telemetry event emitted by a module.
func (l *Logger) LogEvent(ev module.TelemetryEvent, info module.ModuleInfo, params module.Params) error {
	if !ev.Outcome.Valid() {
		return fmt.Errorf("audit: event %q has invalid outcome %q", ev.EventType, ev.Outcome)
	}
	if err := ev.Subject.Validate(); err != nil {
		return fmt.Errorf("audit: event %q subject: %w", ev.EventType, err)
	}
	cl := Classify(ev.Category, ev.EventType)
	eventTime := ev.Timestamp
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}

	st := statusForOutcome(ev.Outcome)

	rec := Record{
		ActivityID:   cl.ActivityID,
		ActivityName: cl.ActivityName,
		CategoryUID:  cl.CategoryUID,
		CategoryName: cl.CategoryName,
		ClassUID:     cl.ClassUID,
		ClassName:    cl.ClassName,
		SeverityID:   st.SeverityID,
		Severity:     st.Severity,
		Time:         epochMS(eventTime),
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
			Params:         map[string]any(params),
			Privileges:     string(info.Privileges),
			Outcome:        string(ev.Outcome),
		},
	}

	switch cl.ClassUID {
	case 1001:
		rec.File = extractFile(ev.EventType, ev.Subject)
	case 1007:
		rec.Process = extractProcess(ev.Subject, l.actor.Process)
	}

	return l.write(rec)
}

// LogLifecycle writes an OCSF audit record for a module lifecycle event (prereq, run, dry-run, cleanup).
func (l *Logger) LogLifecycle(recordType string, info module.ModuleInfo, params module.Params, data LifecycleData) error {
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
		Params:         map[string]any(params),
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

	return l.write(rec)
}

// LogScenario writes an OCSF audit record summarising the outcome of a full scenario run.
func (l *Logger) LogScenario(name, path string, data LifecycleData) error {
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

	return l.write(rec)
}

func (l *Logger) write(rec Record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("audit: marshal record: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return fmt.Errorf("audit: logger is closed")
	}
	b = append(b, '\n')
	n, err := l.f.Write(b)
	if err != nil {
		return fmt.Errorf("audit: write record: %w", err)
	}
	if n != len(b) {
		return fmt.Errorf("audit: write record: %w", io.ErrShortWrite)
	}
	return nil
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
		CmdLine: redactedCommandLine(os.Args),
	}
	if u, err := user.Current(); err == nil {
		proc.User = &OCSFUser{Name: u.Username}
	}
	return &OCSFActor{Process: proc}
}

func redactedCommandLine(args []string) string {
	redacted := append([]string(nil), args...)
	for i := 0; i < len(redacted); i++ {
		switch {
		case redacted[i] == "--param" && i+1 < len(redacted):
			redacted[i+1] = module.RedactedValue
			i++
		case strings.HasPrefix(redacted[i], "--param="):
			redacted[i] = "--param=" + module.RedactedValue
		}
	}
	return strings.Join(redacted, " ")
}

// currentDevice identifies the local host. type_id is Unknown (0) rather
// than a guess at Desktop/Laptop, since nothing here can reliably tell them
// apart; hostname alone satisfies OCSF's "at least one identifying field" rule.
func currentDevice() *OCSFDevice {
	hostname, _ := os.Hostname()
	return &OCSFDevice{TypeID: 0, Hostname: hostname}
}

// extractFile builds the file object required by OCSF file activity from the
// event's typed subject.
func extractFile(eventType string, subject module.Subject) *OCSFFile {
	name := ""
	path := ""
	if subject.File != nil {
		name = subject.File.Name
		path = subject.File.Path
	} else if subject.Resource != nil {
		name = subject.Resource.Name
		path = subject.Resource.Path
	}
	typeID := 1 // Regular File
	if eventType == "dir_create" {
		typeID = 2 // Folder
	}
	if name == "" && path != "" {
		name = filepath.Base(path)
	}
	if name == "" {
		name = eventType
	}
	if path == "" {
		return &OCSFFile{Name: name, TypeID: typeID}
	}
	return &OCSFFile{Name: name, Path: path, TypeID: typeID}
}

// extractProcess builds the process object required by OCSF process activity
// from the event's typed subject.
func extractProcess(subject module.Subject, fallback *OCSFProcess) *OCSFProcess {
	if subject.Process == nil {
		return fallback
	}
	s := subject.Process
	name := s.Name
	if name == "" {
		name = s.Executable
	}
	if name == "" {
		name = s.Command
	}
	return &OCSFProcess{PID: s.PID, Name: name, CmdLine: s.Command}
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
	if data.GenerateError != "" || data.CleanupError != "" {
		return 3, "Medium"
	}
	return 1, "Informational"
}

func lifecycleStatus(data LifecycleData) (int, string) {
	if data.PrereqResult == "fail" || data.GenerateError != "" || data.CleanupError != "" {
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
		if data.GenerateError != "" && data.CleanupError != "" {
			return fmt.Sprintf("Module %s failed: %s; cleanup failed: %s", moduleName, data.GenerateError, data.CleanupError)
		}
		if data.GenerateError != "" {
			return fmt.Sprintf("Module %s failed: %s", moduleName, data.GenerateError)
		}
		if data.CleanupError != "" {
			return fmt.Sprintf("Module %s cleanup failed: %s", moduleName, data.CleanupError)
		}
		return fmt.Sprintf("Module %s completed successfully (%d events emitted)", moduleName, data.EventsEmitted)
	}
}
