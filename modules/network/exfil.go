package network

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type netExfil struct{}

func (n *netExfil) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_exfil",
		Description: "Sends an HTTP POST with a dummy payload to simulate data exfiltration traffic",
		Category:    module.CategoryNetwork,
		Tags:        []string{"exfil", "http", "post", "data-exfiltration"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1041", Name: "Exfiltration Over C2 Channel"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (n *netExfil) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "target", Description: "Target URL for the POST request", Required: false, DefaultValue: "http://127.0.0.1:8080/upload", Example: "http://10.0.0.1/exfil"},
		{Name: "payload_size", Description: "Payload size in bytes", Required: false, DefaultValue: "4096", Example: "1024"},
		{Name: "content_type", Description: "Content-Type header value", Required: false, DefaultValue: "application/octet-stream", Example: "application/json"},
	}
}

func (n *netExfil) CheckPrereqs() error { return nil }

func (n *netExfil) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	target := params.Get("target", "http://127.0.0.1:8080/upload")
	payloadSizeStr := params.Get("payload_size", "4096")
	contentType := params.Get("content_type", "application/octet-stream")
	info := n.Info()

	payloadSize := 4096
	fmt.Sscanf(payloadSizeStr, "%d", &payloadSize) //nolint:errcheck

	payload := make([]byte, payloadSize)
	rand.Read(payload) //nolint:errcheck

	ev := output.NewEvent(info, "http_post_exfil", false, fmt.Sprintf("POST %d bytes to %s", payloadSize, target))
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		ev = output.WithError(ev, err)
		emit(ev)
		return err
	}
	req.Header.Set("Content-Type", contentType)

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		ev.Success = true
		ev.Message = fmt.Sprintf("POST to %s failed (no listener — telemetry generated)", target)
		ev = output.WithDetails(ev, map[string]any{
			"target":       target,
			"payload_size": payloadSize,
			"content_type": contentType,
			"elapsed_ms":   elapsed.Milliseconds(),
			"error":        err.Error(),
		})
	} else {
		_ = resp.Body.Close()
		ev.Success = true
		ev.Message = fmt.Sprintf("POST %d bytes to %s returned %d", payloadSize, target, resp.StatusCode)
		ev = output.WithDetails(ev, map[string]any{
			"target":       target,
			"payload_size": payloadSize,
			"content_type": contentType,
			"status":       resp.StatusCode,
			"elapsed_ms":   elapsed.Milliseconds(),
		})
	}
	emit(ev)
	return nil
}

func (n *netExfil) DryRun(params module.Params) []string {
	target := params.Get("target", "http://127.0.0.1:8080/upload")
	payloadSizeStr := params.Get("payload_size", "4096")
	contentType := params.Get("content_type", "application/octet-stream")
	return []string{
		fmt.Sprintf("HTTP POST %s bytes of %s to %s", payloadSizeStr, contentType, target),
	}
}

func (n *netExfil) Cleanup() error { return nil }

func init() {
	module.Register(&netExfil{})
}
