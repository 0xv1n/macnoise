package network

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/0xv1n/macnoise/internal/output"
	"github.com/0xv1n/macnoise/pkg/module"
)

const defaultHTTPTimeout = 10 * time.Second

type netHTTP struct{}

type httpResult struct {
	url        string
	statusCode int
	elapsed    time.Duration
}

func (n *netHTTP) Info() module.ModuleInfo {
	return module.ModuleInfo{
		Name:        "net_http",
		EventTypes:  []string{"http_get", "http_post"},
		Description: "Sends HTTP requests with an exact method and body",
		Category:    module.CategoryNetwork,
		Tags:        []string{"http", "outbound"},
		Privileges:  module.PrivilegeNone,
		MITRE: []module.MITRE{
			{Technique: "T1071", SubTech: ".001", Name: "Application Layer Protocol: Web Protocols"},
		},
		Author:   "0xv1n",
		MinMacOS: "12.0",
	}
}

func (n *netHTTP) ParamSpecs() []module.ParamSpec {
	return []module.ParamSpec{
		{Name: "target", Description: "Absolute HTTP or HTTPS URL", Type: module.ParamString, Default: "http://example.com", Example: "https://10.0.0.1/collect"},
		{Name: "method", Description: "HTTP request method", Type: module.ParamString, Default: http.MethodGet, Example: http.MethodPost, Choices: []string{http.MethodGet, http.MethodPost}},
		{Name: "body", Description: "Exact request body", Type: module.ParamString, Sensitive: true, Default: "", Example: "decoy payload"},
		{Name: "content_type", Description: "Content-Type header value", Type: module.ParamString, Default: "", Example: "application/json"},
		{Name: "count", Description: "Number of request attempts", Type: module.ParamInteger, Default: 1, Example: 3, Range: &module.IntegerRange{Min: 1}},
		{Name: "interval", Description: "Seconds between requests", Type: module.ParamInteger, Default: 0, Example: 2, Range: &module.IntegerRange{Min: 0}},
		{Name: "jitter", Description: "Percent to randomize each interval by", Type: module.ParamInteger, Default: 0, Example: 30, Range: &module.IntegerRange{Min: 0, Max: 100}},
	}
}

func (n *netHTTP) ValidateParams(params module.Params) error {
	if err := validateHTTPURL(params.String("target", "http://example.com")); err != nil {
		return err
	}
	method := params.String("method", http.MethodGet)
	if method != http.MethodGet && method != http.MethodPost {
		return fmt.Errorf("method must be GET or POST")
	}
	return nil
}

func validateHTTPURL(target string) error {
	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		return fmt.Errorf("target must be an absolute HTTP or HTTPS URL: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("target must be an absolute HTTP or HTTPS URL")
	}
	return nil
}

func (n *netHTTP) CheckPrereqs(ctx context.Context, params module.Params) error {
	return n.ValidateParams(params)
}

func performHTTPRequest(ctx context.Context, method, target, contentType string, body []byte, timeout time.Duration) (httpResult, error) {
	result := httpResult{url: tagURL(target, module.RunIDFromContext(ctx))}
	request, err := http.NewRequestWithContext(ctx, method, result.url, bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	client := http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	start := time.Now()
	response, err := client.Do(request)
	result.elapsed = time.Since(start)
	if err != nil {
		return result, err
	}
	result.statusCode = response.StatusCode
	_ = response.Body.Close()
	return result, nil
}

func jitterInterval(base time.Duration, jitterPct int, random *rand.Rand) time.Duration {
	if jitterPct <= 0 || base <= 0 {
		return base
	}
	if jitterPct > 100 {
		jitterPct = 100
	}
	span := float64(base) * float64(jitterPct) / 100.0
	offset := (random.Float64()*2 - 1) * span
	delay := time.Duration(float64(base) + offset)
	if delay < 0 {
		return 0
	}
	return delay
}

func (n *netHTTP) Generate(ctx context.Context, params module.Params, emit module.EventEmitter) error {
	if err := n.ValidateParams(params); err != nil {
		return err
	}
	method := params.String("method", http.MethodGet)
	target := params.String("target", "http://example.com")
	body := []byte(params.String("body", ""))
	contentType := params.String("content_type", "")
	info := n.Info()
	count := params.Int("count", 1)
	interval := time.Duration(params.Int("interval", 0)) * time.Second
	jitter := params.Int("jitter", 0)
	random := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // request timing, not security

	for attempt := 1; attempt <= count; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, requestErr := performHTTPRequest(ctx, method, target, contentType, body, defaultHTTPTimeout)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		eventType := "http_get"
		if method == http.MethodPost {
			eventType = "http_post"
		}
		ev := output.NewEvent(info, eventType, module.OutcomeError, module.Network("", result.url, ""), fmt.Sprintf("%s %s", method, result.url))
		details := map[string]any{
			"url":           result.url,
			"method":        method,
			"request_bytes": len(body),
			"elapsed_ms":    result.elapsed.Milliseconds(),
			"attempt":       attempt,
			"total":         count,
		}
		if contentType != "" {
			details["content_type"] = contentType
		}
		if requestErr != nil {
			ev = output.WithOutcome(ev, module.OutcomeDenied, requestErr)
			ev.Message = fmt.Sprintf("%s %s failed (telemetry generated)", method, result.url)
		} else {
			ev.Outcome = module.OutcomeExecuted
			ev.Message = fmt.Sprintf("%s %s returned %d", method, result.url, result.statusCode)
			details["status_code"] = result.statusCode
		}
		if err := emit(output.WithDetails(ev, details)); err != nil {
			return err
		}
		if attempt < count {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(jitterInterval(interval, jitter, random)):
			}
		}
	}
	return nil
}

func (n *netHTTP) DryRun(params module.Params) []string {
	method := params.String("method", http.MethodGet)
	target := params.String("target", "http://example.com")
	bodySize := len(params.String("body", ""))
	count := params.Int("count", 1)
	interval := params.Int("interval", 0)
	jitter := params.Int("jitter", 0)
	return []string{fmt.Sprintf("send %d HTTP %s request(s) to %s with %d request bytes and %ds interval (jitter %d%%)", count, method, target, bodySize, interval, jitter)}
}

func (n *netHTTP) Cleanup(ctx context.Context) error { return nil }

func init() {
	module.Register(func() module.Generator { return &netHTTP{} })
}
