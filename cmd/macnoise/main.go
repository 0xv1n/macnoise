// MacNoise - macOS telemetry noise generator for EDR testing and security research.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/0xv1n/macnoise/internal/audit"
	"github.com/0xv1n/macnoise/internal/config"
	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/runner"
	"github.com/0xv1n/macnoise/pkg/module"

	_ "github.com/0xv1n/macnoise/modules/endpoint_security"
	_ "github.com/0xv1n/macnoise/modules/file"
	_ "github.com/0xv1n/macnoise/modules/network"
	_ "github.com/0xv1n/macnoise/modules/plist"
	_ "github.com/0xv1n/macnoise/modules/process"
	_ "github.com/0xv1n/macnoise/modules/service"
	_ "github.com/0xv1n/macnoise/modules/tcc"
	_ "github.com/0xv1n/macnoise/modules/xpc"
)

var (
	globalFormat   string
	globalOutput   string
	globalVerbose  bool
	globalDryRun   bool
	globalTimeout  int
	globalAuditLog string
	globalConfig   string
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
			if !cmd.Flags().Changed("timeout") && cfg.DefaultTimeout > 0 {
				globalTimeout = cfg.DefaultTimeout
			}
			return nil
		},
	}

	root.PersistentFlags().StringVar(&globalFormat, "format", "human", "Output format: human|jsonl")
	root.PersistentFlags().StringVar(&globalOutput, "output", "", "Write output to file (in addition to stdout)")
	root.PersistentFlags().BoolVarP(&globalVerbose, "verbose", "v", false, "Verbose output")
	root.PersistentFlags().BoolVar(&globalDryRun, "dry-run", false, "Preview actions without executing")
	root.PersistentFlags().IntVar(&globalTimeout, "timeout", 30, "Per-module timeout in seconds (0 = no timeout)")
	root.PersistentFlags().StringVar(&globalAuditLog, "audit-log", "", "Write OCSF 1.7.0 JSONL audit records to file")
	root.PersistentFlags().StringVar(&globalConfig, "config", "", "Config YAML file (default: none)")

	root.AddCommand(
		buildRun(),
		buildList(),
		buildInfo(),
		buildScenario(),
		buildCategories(),
		buildVersion(),
	)
	return root
}

func buildEmitter() (*output.Emitter, func(), error) {
	format := output.Format(globalFormat)

	em := output.NewEmitter(format, os.Stdout)
	closeFile := func() {}

	if globalOutput != "" {
		f, err := os.OpenFile(globalOutput, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot open output file: %w", err)
		}
		em = output.NewEmitter(format, os.Stdout, f)
		closeFile = func() { _ = f.Close() }
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

func buildAuditLogger(path string) (*audit.Logger, func(), error) {
	if path == "" {
		return nil, func() {}, nil
	}
	l, err := audit.NewLogger(path, version)
	if err != nil {
		return nil, nil, err
	}
	return l, func() { _ = l.Close() }, nil
}

func buildRunOpts(auditLogger *audit.Logger) runner.Options {
	timeout := time.Duration(globalTimeout) * time.Second
	return runner.Options{
		DryRun:   globalDryRun,
		Timeout:  timeout,
		Verbose:  globalVerbose,
		AuditLog: auditLogger,
	}
}

func buildRun() *cobra.Command {
	var (
		paramFlags []string
		category   string
		runAll     bool
	)

	cmd := &cobra.Command{
		Use:   "run [module]",
		Short: "Run one or more telemetry modules",
		Example: `  macnoise run net_connect --param target=127.0.0.1 --param port=8080
  macnoise run --category network
  macnoise run --all --format jsonl`,
		RunE: func(cmd *cobra.Command, args []string) error {
			em, closeEM, err := buildEmitter()
			if err != nil {
				return err
			}
			defer closeEM()

			auditLogger, closeAL, err := buildAuditLogger(resolveAuditLogPath(""))
			if err != nil {
				return err
			}
			defer closeAL()

			params := parseParams(paramFlags)
			opts := buildRunOpts(auditLogger)
			ctx := context.Background()

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
			var gens []module.Generator
			if catFilter != "" {
				gens = module.ByCategory(module.Category(catFilter))
			} else {
				gens = module.All()
			}
			if len(gens) == 0 {
				fmt.Println("No modules found.")
				return nil
			}
			fmt.Printf("%-25s %-20s %s\n", "MODULE", "CATEGORY", "DESCRIPTION")
			fmt.Println(strings.Repeat("-", 80))
			for _, g := range gens {
				info := g.Info()
				fmt.Printf("%-25s %-20s %s\n", info.Name, info.Category, info.Description)
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
			gen, ok := module.Get(args[0])
			if !ok {
				return fmt.Errorf("module %q not found", args[0])
			}
			info := gen.Info()
			fmt.Printf("Name:        %s\n", info.Name)
			fmt.Printf("Category:    %s\n", info.Category)
			fmt.Printf("Description: %s\n", info.Description)
			fmt.Printf("Privileges:  %s\n", info.Privileges)
			if info.MinMacOS != "" {
				fmt.Printf("Min macOS:   %s\n", info.MinMacOS)
			}
			if len(info.Tags) > 0 {
				fmt.Printf("Tags:        %s\n", strings.Join(info.Tags, ", "))
			}
			if len(info.MITRE) > 0 {
				fmt.Println("MITRE ATT&CK:")
				for _, m := range info.MITRE {
					fmt.Printf("  %s%s - %s\n", m.Technique, m.SubTech, m.Name)
				}
			}
			if info.Author != "" {
				fmt.Printf("Author:      %s\n", info.Author)
			}
			specs := gen.ParamSpecs()
			if len(specs) > 0 {
				fmt.Println("\nParameters:")
				for _, s := range specs {
					req := ""
					if s.Required {
						req = " (required)"
					}
					fmt.Printf("  %-20s %s%s\n", s.Name, s.Description, req)
					if s.DefaultValue != "" {
						fmt.Printf("    default: %s\n", s.DefaultValue)
					}
					if s.Example != "" {
						fmt.Printf("    example: %s\n", s.Example)
					}
				}
			}
			return nil
		},
	}
}

func buildScenario() *cobra.Command {
	return &cobra.Command{
		Use:   "scenario <file.yaml>",
		Short: "Run a YAML scenario file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			em, closeEM, err := buildEmitter()
			if err != nil {
				return err
			}
			defer closeEM()

			scenarioAuditLog := ""
			if sc, err := runner.LoadScenario(args[0]); err == nil {
				scenarioAuditLog = sc.AuditLog
			}

			auditLogger, closeAL, err := buildAuditLogger(resolveAuditLogPath(scenarioAuditLog))
			if err != nil {
				return err
			}
			defer closeAL()

			opts := buildRunOpts(auditLogger)
			return runner.RunScenario(context.Background(), args[0], em.EmitFunc(), opts)
		},
	}
}

func buildCategories() *cobra.Command {
	return &cobra.Command{
		Use:   "categories",
		Short: "List all telemetry categories with module counts",
		RunE: func(cmd *cobra.Command, args []string) error {
			counts := module.CategoryCounts()
			fmt.Printf("%-25s %s\n", "CATEGORY", "MODULES")
			fmt.Println(strings.Repeat("-", 35))
			for _, cat := range module.AllCategories() {
				fmt.Printf("%-25s %d\n", cat, counts[cat])
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
			fmt.Printf("MacNoise %s\n", version)
		},
	}
}

func parseParams(flags []string) module.Params {
	p := module.Params{}
	for _, f := range flags {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) == 2 {
			p[parts[0]] = parts[1]
		}
	}
	return p
}
