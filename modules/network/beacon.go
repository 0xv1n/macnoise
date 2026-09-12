package network

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type c2Beacon struct{}

func (c *c2Beacon) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_beacon",
		EventTypes:  []string{"http_beacon"},
		Description: "Simulates periodic HTTP C2 beaconing traffic",
		Category:    module.CategoryNetwork,
		Tags:        []string{"http", "c2", "beaconing", "periodic"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1071", SubTech: ".001", Name: "Application Layer Protocol: Web Protocols"},
			{Technique: "T1102", Name: "Web Service"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (c *c2Beacon) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "target", Description: "Target URL or host", Type: module.ParamString, Default: "http://example.com", Example: "http://10.0.0.1"},
		{Name: "count", Description: "Number of beacon attempts", Type: module.ParamInteger, Default: 3, Example: 5, Range: &module.IntegerRange{Min: 1}},
		{Name: "interval", Description: "Seconds between beacons", Type: module.ParamInteger, Default: 2, Example: 10, Range: &module.IntegerRange{Min: 0}},
		{Name: "jitter", Description: "Percent to randomise each interval by, 0-100 (0 = fixed)", Type: module.ParamInteger, Default: 0, Example: 30, Range: &module.IntegerRange{Min: 0, Max: 100}},
	}
}

// jitterInterval randomises base by up to jitterPct percent in either
// direction. A perfectly fixed beacon interval is one of the easiest C2
// signals to fingerprint, so real implants jitter and detections look for the
// absence of it. The result is clamped at zero so a large percentage cannot
// produce a negative delay.
func jitterInterval(base time.Duration, jitterPct int, rnd *rand.Rand) time.Duration {
	if jitterPct <= 0 || base <= 0 {
		return base
	}
	if jitterPct > 100 {
		jitterPct = 100
	}
	span := float64(base) * float64(jitterPct) / 100.0
	offset := (rnd.Float64()*2 - 1) * span
	out := time.Duration(float64(base) + offset)
	if out < 0 {
		return 0
	}
	return out
}

func (c *c2Beacon) CheckPrereqs(ctx context.Context, params module.Params) error { return nil }

func (c *c2Beacon) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	target := tagURL(params.String("target", "http://example.com"), module.RunIDFromContext(ctx))
	count := params.Int("count", 3)
	intervalSecs := params.Int("interval", 2)
	interval := time.Duration(intervalSecs) * time.Second
	jitterPct := params.Int("jitter", 0)
	rnd := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // jitter timing, not security

	info := c.Info()
	client := &http.Client{Timeout: 5 * time.Second}

	for i := 1; i <= count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		ev := output.NewEvent(info, "http_beacon", module.OutcomeError, module.Network("", target, ""), fmt.Sprintf("beacon %d/%d to %s", i, count, target))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		var resp *http.Response
		if err == nil {
			resp, err = client.Do(req)
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			ev = output.WithOutcome(ev, module.OutcomeDenied, err)
			ev.Message = fmt.Sprintf("beacon %d/%d to %s (no response — telemetry generated)", i, count, target)
		} else {
			_ = resp.Body.Close()
			ev.Outcome = module.OutcomeExecuted
			ev.Message = fmt.Sprintf("beacon %d/%d to %s returned %d", i, count, target, resp.StatusCode)
			ev = output.WithDetails(ev, map[string]any{"attempt": i, "total": count, "url": target, "status": resp.StatusCode})
		}
		if err := emit(ev); err != nil {
			return err
		}

		if i < count {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(jitterInterval(interval, jitterPct, rnd)):
			}
		}
	}
	return nil
}

func (c *c2Beacon) DryRun(params module.Params) []string {
	target := params.String("target", "http://example.com")
	count := params.Int("count", 3)
	interval := params.Int("interval", 2)
	jitter := params.Int("jitter", 0)
	return []string{
		fmt.Sprintf("send %d HTTP GET requests to %s with %ds interval (jitter %d%%)", count, target, interval, jitter),
	}
}

func (c *c2Beacon) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &c2Beacon{} })
}
