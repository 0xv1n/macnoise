package service

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/internal/prereqs"
	"github.com/0xv1n/macnoise/pkg/module"
)

type svcEnumerate struct{}

func (s *svcEnumerate) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "svc_enumerate",
		EventTypes:  []string{"service_enumerate"},
		Description: "Enumerates launchd services in the current user's GUI domain, the system domain, or both",
		Category:    module.CategoryService,
		Tags:        []string{"launchd", "launchctl", "service", "enumeration"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1007", Name: "System Service Discovery"},
		},
		Author:   "0xv1n",
		MinMacOS: "10.10",
	}
}

func (s *svcEnumerate) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "scope", Description: "Launchd scope to enumerate", Type: module.ParamString, Default: "all", Example: "system", Choices: []string{"all", "user", "system"}},
		{Name: "filter", Description: "Filter string for service labels (empty = all)", Type: module.ParamString, Default: "com.apple", Example: "com.apple.security"},
		{Name: "max_results", Description: "Maximum matching services per launchd domain", Type: module.ParamInteger, Default: 10, Example: 20, Range: &module.IntegerRange{Min: 1}},
	}
}

func (s *svcEnumerate) CheckPrereqs(ctx context.Context, params module.Params) error {
	return prereqs.CheckCommand("launchctl")
}

func parseLaunchdServices(out, filter string, max int) []string {
	services := make([]string, 0)
	inServices := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !inServices {
			if strings.HasPrefix(trimmed, "services") && strings.HasSuffix(trimmed, "{") {
				inServices = true
			}
			continue
		}
		if trimmed == "}" {
			break
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}
		label := fields[len(fields)-1]
		if filter != "" && !strings.Contains(label, filter) {
			continue
		}
		services = append(services, label)
		if len(services) == max {
			break
		}
	}
	return services
}

func enumerationDomains(scope, userDomain string) []string {
	switch scope {
	case "user":
		return []string{userDomain}
	case "system":
		return []string{systemDomain}
	default:
		return []string{userDomain, systemDomain}
	}
}

func (s *svcEnumerate) enumerateDomain(ctx context.Context, domain, filter string, max int, emit module.EventEmitter) error {
	info := s.Info()
	ev := output.NewEvent(info, "service_enumerate", module.OutcomeError, module.Resource("launchd_domain", domain, ""), fmt.Sprintf("enumerating services in launchd domain %s", domain))
	details := map[string]any{"domain": domain, "filter": filter}

	out, err := exec.CommandContext(ctx, "launchctl", "print", domain).CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ev = output.WithOutcome(ev, module.OutcomeDenied, fmt.Errorf("launchctl print %s: %v: %s", domain, err, out))
		ev.Message = fmt.Sprintf("could not enumerate launchd domain %s", domain)
		details["accessible"] = false
		return emit(output.WithDetails(ev, details))
	}

	services := parseLaunchdServices(string(out), filter, max)
	ev.Outcome = module.OutcomeExecuted
	ev.Message = fmt.Sprintf("enumerated %d services in %s matching %q", len(services), domain, filter)
	details["accessible"] = true
	details["service_count"] = len(services)
	details["services"] = services
	return emit(output.WithDetails(ev, details))
}

func (s *svcEnumerate) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	scope := params.String("scope", "all")
	filter := params.String("filter", "com.apple")
	max := params.Int("max_results", 10)

	userDomain := guiDomain(0)
	user, err := resolveLaunchdUser()
	if err == nil {
		userDomain = guiDomain(user.uid)
	}
	for _, domain := range enumerationDomains(scope, userDomain) {
		if err := s.enumerateDomain(ctx, domain, filter, max, emit); err != nil {
			return err
		}
	}
	return nil
}

func (s *svcEnumerate) DryRun(params module.Params) []string {
	scope := params.String("scope", "all")
	filter := params.String("filter", "com.apple")
	userDomain := "gui/<uid>"
	if user, err := resolveLaunchdUser(); err == nil {
		userDomain = guiDomain(user.uid)
	}
	steps := make([]string, 0, 3)
	for _, domain := range enumerationDomains(scope, userDomain) {
		steps = append(steps, fmt.Sprintf("launchctl print %s", domain))
	}
	return append(steps, fmt.Sprintf("filter service labels matching %q", filter))
}

func (s *svcEnumerate) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &svcEnumerate{} })
}
