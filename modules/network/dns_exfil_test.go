package network

import (
	"fmt"
	"strings"
	"testing"

	"github.com/0xv1n/macnoise/pkg/module"
)

func TestEncodeExfilPayload_DNSSafe(t *testing.T) {
	encoded := encodeExfilPayload("macnoise-exfil-test")
	for _, c := range encoded {
		if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
			t.Fatalf("encoded payload contains non-DNS-safe char %q: %s", c, encoded)
		}
	}
}

func TestEncodeExfilPayload_NoPadding(t *testing.T) {
	encoded := encodeExfilPayload("test")
	if strings.Contains(encoded, "=") {
		t.Fatalf("encoded payload contains padding: %s", encoded)
	}
}

func TestChunkExfilLabels_RespectMax(t *testing.T) {
	input := strings.Repeat("a", 200)
	chunks := chunkExfilLabels(input, 63)
	for i, chunk := range chunks {
		if len(chunk) > 63 {
			t.Errorf("chunk %d has %d chars, max is 63", i, len(chunk))
		}
	}
	joined := strings.Join(chunks, "")
	if joined != input {
		t.Error("chunks do not reassemble to original")
	}
}

func TestChunkExfilLabels_ShortInput(t *testing.T) {
	chunks := chunkExfilLabels("abc", 63)
	if len(chunks) != 1 || chunks[0] != "abc" {
		t.Errorf("short input produced %v, want [abc]", chunks)
	}
}

func TestExfilQueries_DefaultPayload(t *testing.T) {
	queries := exfilQueries("macnoise-exfil-test", defaultExfilDomain)
	if len(queries) == 0 {
		t.Fatal("expected at least one query")
	}
	for i, q := range queries {
		if !strings.HasSuffix(q, "."+defaultExfilDomain) {
			t.Errorf("query %d missing base domain suffix: %s", i, q)
		}
		if len(q) > dnsNameMax {
			t.Errorf("query %d exceeds DNS name max (%d): %s", i, len(q), q)
		}
		parts := strings.SplitN(q, ".", 2)
		if len(parts[0]) > dnsLabelMax {
			t.Errorf("query %d label exceeds 63 chars (%d): %s", i, len(parts[0]), q)
		}
	}
}

func TestExfilQueries_ContainsSequenceNumber(t *testing.T) {
	queries := exfilQueries("macnoise-exfil-test", defaultExfilDomain)
	for i, q := range queries {
		seq := strings.SplitN(q, ".", 3)[1]
		want := fmt.Sprintf("%d", i)
		if seq != want {
			t.Errorf("query %d has seq %q, want %q", i, seq, want)
		}
	}
}

func TestExfilQueries_NameTooLong(t *testing.T) {
	longDomain := strings.Repeat("x", 200) + ".invalid"
	queries := exfilQueries("test", longDomain)
	for _, q := range queries {
		if len(q) > dnsNameMax {
			t.Errorf("query exceeds DNS name max: %s", q)
		}
	}
}

func TestDNSExfilDryRunMatchesQueries(t *testing.T) {
	mod := &netDNSExfil{}
	steps := mod.DryRun(module.Params{})
	queries := exfilQueries("macnoise-exfil-test", defaultExfilDomain)
	if len(steps) != len(queries) {
		t.Errorf("dry run listed %d steps, want %d", len(steps), len(queries))
	}
}
