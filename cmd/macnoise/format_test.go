package main

import (
	"testing"

	"github.com/0xv1n/macnoise/internal/output"
)

// An unrecognised --format used to fall through the emitter's switch to human
// output, so anyone who mistyped it while piping to a parser silently got the
// wrong format instead of an error.
func TestParseFormat(t *testing.T) {
	tests := []struct {
		in      string
		want    output.Format
		wantErr bool
	}{
		{in: "human", want: output.FormatHuman},
		{in: "jsonl", want: output.FormatJSONL},
		{in: "garbage", wantErr: true},
		{in: "JSONL", wantErr: true},
		{in: "json", wantErr: true},
		{in: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseFormat(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseFormat(%q) = %q, want an error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFormat(%q): unexpected error %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("parseFormat(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
