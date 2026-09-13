package network

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

type netExfil struct{}

func (n *netExfil) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_exfil",
		EventTypes:  []string{"http_post_exfil"},
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
		{Name: "target", Description: "Target URL for the POST request", Type: module.ParamString, Default: "http://127.0.0.1:8080/upload", Example: "http://10.0.0.1/exfil"},
		{Name: "payload_size", Description: "Payload size in bytes", Type: module.ParamInteger, Default: 4096, Example: 1024, Range: &module.IntegerRange{Min: 0}},
		{Name: "content_type", Description: "Content-Type header value", Type: module.ParamString, Default: "application/octet-stream", Example: "application/json"},
	}
}

func (n *netExfil) ValidateParams(params module.Params) error {
	return validateHTTPURL(params.String("target", "http://127.0.0.1:8080/upload"))
}

func (n *netExfil) CheckPrereqs(ctx context.Context, params module.Params) error {
	return n.ValidateParams(params)
}

func (n *netExfil) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := n.ValidateParams(params); err != nil {
		return err
	}
	target := params.String("target", "http://127.0.0.1:8080/upload")
	payloadSize := params.Int("payload_size", 4096)
	contentType := params.String("content_type", "application/octet-stream")
	info := n.Info()

	payload := make([]byte, payloadSize)
	if _, err := rand.Read(payload); err != nil {
		ev := output.NewEvent(info, "http_post_exfil", module.OutcomeError, module.Network("", tagURL(target, module.RunIDFromContext(ctx)), ""), fmt.Sprintf("generating %d request bytes", payloadSize))
		ev = output.WithError(ev, err)
		return errors.Join(err, emit(ev))
	}
	result, err := performHTTPRequest(ctx, http.MethodPost, target, contentType, payload, defaultHTTPTimeout)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	ev := output.NewEvent(info, "http_post_exfil", module.OutcomeError, module.Network("", result.url, ""), fmt.Sprintf("POST %d bytes to %s", payloadSize, result.url))
	if err != nil {
		ev = output.WithOutcome(ev, module.OutcomeDenied, err)
		ev.Message = fmt.Sprintf("POST to %s failed (no listener - telemetry generated)", result.url)
		ev = output.WithDetails(ev, map[string]any{
			"target":       result.url,
			"payload_size": payloadSize,
			"content_type": contentType,
			"elapsed_ms":   result.elapsed.Milliseconds(),
			"error":        err.Error(),
		})
	} else {
		ev.Outcome = module.OutcomeExecuted
		ev.Message = fmt.Sprintf("POST %d bytes to %s returned %d", payloadSize, result.url, result.statusCode)
		ev = output.WithDetails(ev, map[string]any{
			"target":       result.url,
			"payload_size": payloadSize,
			"content_type": contentType,
			"status":       result.statusCode,
			"elapsed_ms":   result.elapsed.Milliseconds(),
		})
	}
	return emit(ev)
}

func (n *netExfil) DryRun(params module.Params) []string {
	target := params.String("target", "http://127.0.0.1:8080/upload")
	payloadSize := params.Int("payload_size", 4096)
	contentType := params.String("content_type", "application/octet-stream")
	return []string{
		fmt.Sprintf("HTTP POST %d bytes of %s to %s", payloadSize, contentType, target),
	}
}

func (n *netExfil) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &netExfil{} })
}
