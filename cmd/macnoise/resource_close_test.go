//go:build unix

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xv1n/macnoise/internal/audit"
	"github.com/0xv1n/macnoise/internal/output"
)

func TestRunReportsOutputCloseErrors(t *testing.T) {
	preserveCommandGlobals(t)
	globalFormat = string(output.FormatHuman)
	globalOutput = ""
	globalAuditLog = ""
	globalDryRun = true
	globalRunID = "close-error-test"

	outputCloseErr := errors.New("output close failed")
	auditCloseErr := errors.New("audit close failed")
	var outputClosed, auditClosed bool
	resources := commandResources{
		emitter: func(w io.Writer) (*output.Emitter, func() error, error) {
			return output.NewEmitter(output.FormatHuman, w), func() error {
				outputClosed = true
				return outputCloseErr
			}, nil
		},
		auditLogger: func(string, string) (*audit.Logger, func() error, error) {
			return nil, func() error {
				auditClosed = true
				return auditCloseErr
			}, nil
		},
	}

	cmd := buildRun(resources)
	if err := cmd.Flags().Set("param", "base_dir="+t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("param", "filename=close-error-test.txt"); err != nil {
		t.Fatal(err)
	}
	err := cmd.RunE(cmd, []string{"file_create"})
	if !errors.Is(err, outputCloseErr) || !errors.Is(err, auditCloseErr) {
		t.Fatalf("RunE error = %v, want both close errors", err)
	}
	if !outputClosed || !auditClosed {
		t.Fatalf("closers called: output=%v audit=%v, want both", outputClosed, auditClosed)
	}
}

func TestRunPreservesAuditOpenErrorAndClosesOutput(t *testing.T) {
	preserveCommandGlobals(t)
	globalFormat = string(output.FormatHuman)
	globalOutput = ""
	globalAuditLog = ""
	globalRunID = "close-error-test"

	outputCloseErr := errors.New("output close failed")
	auditOpenErr := errors.New("audit open failed")
	var outputClosed bool
	resources := commandResources{
		emitter: func(w io.Writer) (*output.Emitter, func() error, error) {
			return output.NewEmitter(output.FormatHuman, w), func() error {
				outputClosed = true
				return outputCloseErr
			}, nil
		},
		auditLogger: func(string, string) (*audit.Logger, func() error, error) {
			return nil, nil, auditOpenErr
		},
	}

	cmd := buildRun(resources)
	err := cmd.RunE(cmd, []string{"file_create"})
	if !errors.Is(err, auditOpenErr) || !errors.Is(err, outputCloseErr) {
		t.Fatalf("RunE error = %v, want audit-open and output-close errors", err)
	}
	if !outputClosed {
		t.Fatal("output closer was not called after the audit logger failed to open")
	}
}

func TestScenarioReportsCloseErrorsAndPreservesCommandError(t *testing.T) {
	preserveCommandGlobals(t)
	globalFormat = string(output.FormatHuman)
	globalOutput = ""
	globalAuditLog = ""
	globalDryRun = true
	globalRunID = "close-error-test"

	scenarioPath := filepath.Join(t.TempDir(), "close-errors.yaml")
	baseDir := t.TempDir()
	scenario := "version: 1\nname: close errors\nsteps:\n  - module: file_create\n    params:\n      base_dir: " + baseDir + "\n      filename: close-error-test.txt\n      content: close error test\n"
	if err := os.WriteFile(scenarioPath, []byte(scenario), 0o600); err != nil {
		t.Fatal(err)
	}
	outputCloseErr := errors.New("output close failed")
	auditCloseErr := errors.New("audit close failed")
	var outputClosed, auditClosed bool
	resources := commandResources{
		emitter: func(w io.Writer) (*output.Emitter, func() error, error) {
			return output.NewEmitter(output.FormatHuman, w), func() error {
				outputClosed = true
				return outputCloseErr
			}, nil
		},
		auditLogger: func(string, string) (*audit.Logger, func() error, error) {
			return nil, func() error {
				auditClosed = true
				return auditCloseErr
			}, nil
		},
	}

	cmd := buildScenario(resources)
	reportPath := filepath.Join(t.TempDir(), "missing", "report.json")
	if err := cmd.Flags().Set("report", reportPath); err != nil {
		t.Fatal(err)
	}
	err := cmd.RunE(cmd, []string{scenarioPath})
	if !errors.Is(err, os.ErrNotExist) || !errors.Is(err, outputCloseErr) || !errors.Is(err, auditCloseErr) {
		t.Fatalf("RunE error = %v, want report and both close errors", err)
	}
	if !outputClosed || !auditClosed {
		t.Fatalf("closers called: output=%v audit=%v, want both", outputClosed, auditClosed)
	}
}
