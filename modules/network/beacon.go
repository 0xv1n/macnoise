package network

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type c2Beacon struct{}

func (c *c2Beacon) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_beacon",
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
		{Name: "target", Description: "Target URL or host", Required: false, DefaultValue: "http://example.com", Example: "http://10.0.0.1"},
		{Name: "count", Description: "Number of beacon attempts", Required: false, DefaultValue: "3", Example: "5"},
		{Name: "interval", Description: "Seconds between beacons", Required: false, DefaultValue: "2", Example: "10"},
	}
}

func (c *c2Beacon) CheckPrereqs() error { return nil }

func (c *c2Beacon) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	target := params.Get("target", "http://example.com")
	countStr := params.Get("count", "3")
	intervalStr := params.Get("interval", "2")

	count := 3
	fmt.Sscanf(countStr, "%d", &count)         //nolint:errcheck
	intervalSecs := 2
	fmt.Sscanf(intervalStr, "%d", &intervalSecs) //nolint:errcheck
	interval := time.Duration(intervalSecs) * time.Second

	info := c.Info()
	client := &http.Client{Timeout: 5 * time.Second}

	for i := 1; i <= count; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		ev := output.NewEvent(info, "http_beacon", false, fmt.Sprintf("beacon %d/%d to %s", i, count, target))
		resp, err := client.Get(target)
		if err != nil {
			ev = output.WithError(ev, err)
			ev.Success = true
			ev.Message = fmt.Sprintf("beacon %d/%d to %s (no response — telemetry generated)", i, count, target)
		} else {
			_ = resp.Body.Close()
			ev.Success = true
			ev.Message = fmt.Sprintf("beacon %d/%d to %s returned %d", i, count, target, resp.StatusCode)
			ev = output.WithDetails(ev, map[string]any{"attempt": i, "total": count, "url": target, "status": resp.StatusCode})
		}
		emit(ev)

		if i < count {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
		}
	}
	return nil
}

func (c *c2Beacon) DryRun(params module.Params) []string {
	target := params.Get("target", "http://example.com")
	countStr := params.Get("count", "3")
	intervalStr := params.Get("interval", "2")
	return []string{
		fmt.Sprintf("send %s HTTP GET requests to %s with %ss interval", countStr, target, intervalStr),
	}
}

func (c *c2Beacon) Cleanup() error { return nil }

func init() {
	module.Register(&c2Beacon{})
}
