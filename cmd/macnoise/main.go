// MacNoise - macOS telemetry noise generator for EDR testing and security research.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/0xv1n/macnoise/internal/audit"
	"github.com/0xv1n/macnoise/internal/config"
	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/runner"
	"github.com/0xv1n/macnoise/pkg/module"

	_ "github.com/0xv1n/macnoise/modules/credential"
	_ "github.com/0xv1n/macnoise/modules/evasion"
	_ "github.com/0xv1n/macnoise/modules/file"
	_ "github.com/0xv1n/macnoise/modules/network"
	_ "github.com/0xv1n/macnoise/modules/plist"
	_ "github.com/0xv1n/macnoise/modules/process"
	_ "github.com/0xv1n/macnoise/modules/service"
	_ "github.com/0xv1n/macnoise/modules/tcc"
	_ "github.com/0xv1n/macnoise/modules/volume"
)

var (
	globalFormat    string
	globalOutput    string
	globalVerbose   bool
	globalDryRun    bool
	globalNoCleanup bool
	globalTimeout   int
	globalAuditLog  string
	globalConfig    string
	globalRunID     string
)

var loadedConfig config.Config

func main() {
	root := buildRoot()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "macnoise",
		Short: "macOS telemetry noise generator for EDR testing",
		Long: `MacNoise generates realistic macOS telemetry noise for security research,
EDR validation, and detection engineering.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(globalConfig)
			if err != nil {
				return err
			}
			loadedConfig = cfg
			if !cmd.Flags().Changed("format") && cfg.DefaultFormat != "" {
				globalFormat = cfg.DefaultFormat
			}
			if !cmd.Flags().Changed("timeout") {
				globalTimeout = cfg.DefaultTimeout
			}
			if !cmd.Flags().Changed("output") && cfg.OutputFile != "" {
				globalOutput = cfg.OutputFile
			}
			if globalTimeout < 0 {
				return errors.New("--timeout must be 0 or greater")
			}
			return nil
		},
	}

	root.PersistentFlags().StringVar(&globalFormat, "format", "human", "Output format: human|jsonl")
	root.PersistentFlags().StringVar(&globalOutput, "output", "", "Write output to file (in addition to stdout)")
	root.PersistentFlags().BoolVarP(&globalVerbose, "verbose", "v", false, "Verbose output")
	root.PersistentFlags().BoolVar(&globalDryRun, "dry-run", false, "Preview actions without executing")
	root.PersistentFlags().BoolVar(&globalNoCleanup, "no-cleanup", false, "Leave module artifacts in place so the persistence itself can be detected")
	root.PersistentFlags().IntVar(&globalTimeout, "timeout", 30, "Per-module timeout in seconds (0 = no timeout)")
	root.PersistentFlags().StringVar(&globalAuditLog, "audit-log", "", "Write OCSF 1.7.0 JSONL audit records to file")
	root.PersistentFlags().StringVar(&globalConfig, "config", "", "Config YAML file (default: none)")
	root.PersistentFlags().StringVar(&globalRunID, "run-id", "", "Correlation ID for this run (auto-generated if omitted)")

	resources := commandResources{emitter: buildEmitter, auditLogger: buildAuditLogger}
	root.AddCommand(
		buildRun(resources),
		buildList(),
		buildInfo(),
		buildScenario(resources),
		buildCategories(),
		buildVersion(),
	)
	return root
}

// parseFormat rejects an unknown --format instead of letting the emitter fall
// back to human output, which silently produced the wrong format for anyone
// who mistyped it while piping to a parser.
func parseFormat(s string) (output.Format, error) {
	switch f := output.Format(s); f {
	case output.FormatHuman, output.FormatJSONL:
		return f, nil
	default:
		return "", fmt.Errorf("invalid --format %q: must be %q or %q", s, output.FormatHuman, output.FormatJSONL)
	}
}

type commandResources struct {
	emitter     func(io.Writer) (*output.Emitter, func() error, error)
	auditLogger func(string, string) (*audit.Logger, func() error, error)
}

func buildEmitter(w io.Writer) (*output.Emitter, func() error, error) {
	format, err := parseFormat(globalFormat)
	if err != nil {
		return nil, nil, err
	}

	em := output.NewEmitter(format, w)
	closeFile := func() error { return nil }

	if globalOutput != "" {
		f, err := os.OpenFile(globalOutput, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot open output file: %w", err)
		}
		em = output.NewEmitter(format, w, f)
		closeFile = f.Close
	}

	return em, closeFile, nil
}

func resolveAuditLogPath(scenarioAuditLog string) string {
	if globalAuditLog != "" {
		return globalAuditLog
	}
	if scenarioAuditLog != "" {
		return scenarioAuditLog
	}
	return loadedConfig.AuditLog
}

func buildAuditLogger(path, runID string) (*audit.Logger, func() error, error) {
	if path == "" {
		return nil, func() error { return nil }, nil
	}
	l, err := audit.NewLogger(path, version, runID)
	if err != nil {
		return nil, nil, err
	}
	return l, l.Close, nil
}

// signalContext returns a context that is cancelled on SIGINT or SIGTERM.
//
// Several modules install real persistence (LaunchAgents, cron entries, shell
// profile blocks, defaults keys) that only the runner's Cleanup step removes.
// Without a cancellable context an interrupted run leaves those artifacts on
// the host, so the signal must reach the module rather than killing the process.
//
// After the first signal, delivery is stopped so the default disposition is
// restored: a second Ctrl-C aborts immediately rather than trapping an operator
// behind a slow or wedged cleanup.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	go func() {
		select {
		case <-ch:
			fmt.Fprintln(os.Stderr, "\ninterrupted - running module cleanup (Ctrl-C again to abort immediately)")
			signal.Stop(ch)
			cancel()
		case <-ctx.Done():
		}
	}()

	return ctx, func() {
		signal.Stop(ch)
		cancel()
	}
}

func resolveRunID() string {
	if globalRunID != "" {
		return globalRunID
	}
	return audit.GenerateRunID()
}

func buildRunOpts(auditLogger *audit.Logger, runID string) runner.Options {
	timeout := time.Duration(globalTimeout) * time.Second
	return runner.Options{
		DryRun:    globalDryRun,
		NoCleanup: globalNoCleanup,
		Timeout:   timeout,
		Verbose:   globalVerbose,
		AuditLog:  auditLogger,
		RunID:     runID,
	}
}

func buildRun(resources commandResources) *cobra.Command {
	var (
		paramFlags []string
		category   string
		runAll     bool
	)

	cmd := &cobra.Command{
		Use:   "run [module]",
		Short: "Run one or more telemetry modules",
		// Without this, `macnoise run a b` fell through to the catch-all
		// "specify a module name" error, which is confusing advice when the
		// user did specify one.
		Args: cobra.MaximumNArgs(1),
		Example: `  macnoise run net_connect --param target=127.0.0.1 --param port=8080
  macnoise run --category network
  macnoise run --all --format jsonl`,
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			params, err := parseParams(paramFlags)
			if err != nil {
				return err
			}
			em, closeEM, err := resources.emitter(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			defer func() { resultErr = errors.Join(resultErr, closeEM()) }()

			runID := resolveRunID()
			auditLogger, closeAL, err := resources.auditLogger(resolveAuditLogPath(""), runID)
			if err != nil {
				return err
			}
			defer func() { resultErr = errors.Join(resultErr, closeAL()) }()

			fmt.Fprintf(os.Stderr, "run_id=%s\n", runID)

			opts := buildRunOpts(auditLogger, runID)
			ctx, stop := signalContext()
			defer stop()

			switch {
			case runAll:
				return runner.RunMany(ctx, module.All(), params, em.EmitFunc(), opts)

			case category != "":
				gens := module.ByCategory(module.Category(category))
				if len(gens) == 0 {
					return fmt.Errorf("no modules found for category %q", category)
				}
				return runner.RunMany(ctx, gens, params, em.EmitFunc(), opts)

			case len(args) == 1:
				gen, ok := module.Get(args[0])
				if !ok {
					return fmt.Errorf("module %q not found — run 'macnoise list' to see available modules", args[0])
				}
				return runner.RunSingle(ctx, gen, params, em.EmitFunc(), opts)

			default:
				return fmt.Errorf("specify a module name, --category <cat>, or --all")
			}
		},
	}

	cmd.Flags().StringArrayVar(&paramFlags, "param", nil, "Module parameter as key=value (repeatable)")
	cmd.Flags().StringVar(&category, "category", "", "Run all modules in this category")
	cmd.Flags().BoolVar(&runAll, "all", false, "Run all registered modules")
	return cmd
}

func buildList() *cobra.Command {
	var catFilter string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available telemetry modules",
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := parseFormat(globalFormat)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			var gens []module.Generator
			if catFilter != "" {
				gens = module.ByCategory(module.Category(catFilter))
			} else {
				gens = module.All()
			}

			if format == output.FormatJSONL {
				enc := json.NewEncoder(cmd.OutOrStdout())
				for _, g := range gens {
					if err := enc.Encode(module.NewCatalogEntry(g)); err != nil {
						return err
					}
				}
				return nil
			}

			if len(gens) == 0 {
				_, _ = fmt.Fprintln(out, "No modules found.")
				return nil
			}
			_, _ = fmt.Fprintf(out, "%-25s %-20s %s\n", "MODULE", "CATEGORY", "DESCRIPTION")
			_, _ = fmt.Fprintln(out, strings.Repeat("-", 80))
			for _, g := range gens {
				info := g.Info()
				_, _ = fmt.Fprintf(out, "%-25s %-20s %s\n", info.Name, info.Category, info.Description)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&catFilter, "category", "", "Filter by category")
	return cmd
}

func buildInfo() *cobra.Command {
	return &cobra.Command{
		Use:   "info <module>",
		Short: "Show detailed module metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			gen, ok := module.Get(args[0])
			if !ok {
				return fmt.Errorf("module %q not found", args[0])
			}
			info := gen.Info()
			_, _ = fmt.Fprintf(out, "Name:        %s\n", info.Name)
			_, _ = fmt.Fprintf(out, "Category:    %s\n", info.Category)
			_, _ = fmt.Fprintf(out, "Description: %s\n", info.Description)
			_, _ = fmt.Fprintf(out, "Privileges:  %s\n", info.Privileges)
			if info.MinMacOS != "" {
				_, _ = fmt.Fprintf(out, "Min macOS:   %s\n", info.MinMacOS)
			}
			if len(info.Tags) > 0 {
				_, _ = fmt.Fprintf(out, "Tags:        %s\n", strings.Join(info.Tags, ", "))
			}
			if len(info.MITRE) > 0 {
				_, _ = fmt.Fprintln(out, "MITRE ATT&CK:")
				for _, m := range info.MITRE {
					_, _ = fmt.Fprintf(out, "  %s%s - %s\n", m.Technique, m.SubTech, m.Name)
				}
			}
			if info.Author != "" {
				_, _ = fmt.Fprintf(out, "Author:      %s\n", info.Author)
			}
			specs := gen.ParamSpecs()
			if len(specs) > 0 {
				_, _ = fmt.Fprintln(out, "\nParameters:")
				for _, s := range specs {
					req := ""
					if s.Required {
						req = " (required)"
					}
					_, _ = fmt.Fprintf(out, "  %-20s %s%s\n", s.Name+" ("+string(s.Type)+")", s.Description, req)
					if s.Default != nil {
						_, _ = fmt.Fprintf(out, "    default: %v\n", s.Default)
					}
					if s.Example != nil {
						_, _ = fmt.Fprintf(out, "    example: %v\n", s.Example)
					}
				}
			}
			if provider, ok := gen.(module.OutputProvider); ok && len(provider.OutputSpecs()) > 0 {
				_, _ = fmt.Fprintln(out, "\nOutputs:")
				for _, spec := range provider.OutputSpecs() {
					_, _ = fmt.Fprintf(out, "  %-20s %s\n", spec.Name+" ("+string(spec.Type)+")", spec.Description)
				}
			}
			return nil
		},
	}
}

func buildScenario(resources commandResources) *cobra.Command {
	var (
		inputFlags []string
		reportPath string
	)
	cmd := &cobra.Command{
		Use:   "scenario <file.yaml>",
		Short: "Run a YAML scenario file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (resultErr error) {
			inputs, err := parseParams(inputFlags)
			if err != nil {
				return fmt.Errorf("scenario input: %w", err)
			}
			prepared, err := runner.PrepareScenario(args[0], inputs, nil)
			if err != nil {
				return err
			}
			em, closeEM, err := resources.emitter(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			defer func() { resultErr = errors.Join(resultErr, closeEM()) }()

			runID := resolveRunID()
			auditLogger, closeAL, err := resources.auditLogger(resolveAuditLogPath(prepared.AuditLog()), runID)
			if err != nil {
				return err
			}
			defer func() { resultErr = errors.Join(resultErr, closeAL()) }()

			fmt.Fprintf(os.Stderr, "run_id=%s\n", runID)

			opts := buildRunOpts(auditLogger, runID)
			ctx, stop := signalContext()
			defer stop()

			report, runErr := prepared.Run(ctx, em.EmitFunc(), opts)
			if reportPath != "" {
				data, err := json.MarshalIndent(report, "", "  ")
				if err == nil {
					data = append(data, '\n')
					err = os.WriteFile(reportPath, data, 0o600)
				}
				if err != nil {
					runErr = errors.Join(runErr, fmt.Errorf("write scenario report: %w", err))
				}
			}
			fmt.Fprintf(os.Stderr, "scenario_status=%s\n", report.Status)
			return runErr
		},
	}
	cmd.Flags().StringArrayVar(&inputFlags, "input", nil, "Scenario input as key=value (repeatable)")
	cmd.Flags().StringVar(&reportPath, "report", "", "Write the scenario execution report as JSON")
	return cmd
}

func buildCategories() *cobra.Command {
	return &cobra.Command{
		Use:   "categories",
		Short: "List all telemetry categories with module counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			counts := module.CategoryCounts()
			_, _ = fmt.Fprintf(out, "%-25s %s\n", "CATEGORY", "MODULES")
			_, _ = fmt.Fprintln(out, strings.Repeat("-", 35))
			for _, cat := range module.AllCategories() {
				_, _ = fmt.Fprintf(out, "%-25s %d\n", cat, counts[cat])
			}
			return nil
		},
	}
}

func buildVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "MacNoise %s\n", version)
		},
	}
}

func parseParams(flags []string) (module.Params, error) {
	p := module.Params{}
	for _, f := range flags {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, fmt.Errorf("invalid --param %q: expected key=value", f)
		}
		if existing, exists := p[parts[0]]; exists {
			if values, ok := existing.([]any); ok {
				p[parts[0]] = append(values, parts[1])
			} else {
				p[parts[0]] = []any{existing, parts[1]}
			}
			continue
		}
		p[parts[0]] = parts[1]
	}
	return p, nil
}
