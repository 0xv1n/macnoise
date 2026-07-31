package service

import (
	"errors"
	"testing"
)

// classifyCrontabList must never mistake a permission or access failure for
// an empty crontab: doing so is what let Generate silently overwrite a real
// crontab when `crontab -l` was denied rather than genuinely empty.
func TestClassifyCrontabList(t *testing.T) {
	tests := []struct {
		name         string
		out          string
		err          error
		wantSafe     bool
		wantExisting string
	}{
		{
			name:         "success with existing entries",
			out:          "*/5 * * * * /usr/bin/true\n",
			err:          nil,
			wantSafe:     true,
			wantExisting: "*/5 * * * * /usr/bin/true\n",
		},
		{
			name:         "success with no error and empty content",
			out:          "",
			err:          nil,
			wantSafe:     true,
			wantExisting: "",
		},
		{
			name:         "genuinely no crontab, macOS wording",
			out:          "crontab: no crontab for gdejesus\n",
			err:          errors.New("exit status 1"),
			wantSafe:     true,
			wantExisting: "",
		},
		{
			name:         "genuinely no crontab, unprefixed wording",
			out:          "no crontab for root\n",
			err:          errors.New("exit status 1"),
			wantSafe:     true,
			wantExisting: "",
		},
		{
			name:         "match is case-insensitive",
			out:          "CRONTAB: NO CRONTAB FOR root\n",
			err:          errors.New("exit status 1"),
			wantSafe:     true,
			wantExisting: "",
		},
		{
			name:     "permission denied must not be treated as empty",
			out:      "crontab: operation not permitted\n",
			err:      errors.New("exit status 1"),
			wantSafe: false,
		},
		{
			name:     "unrecognized error text must not be treated as empty",
			out:      "crontab: some future error we have never seen\n",
			err:      errors.New("exit status 1"),
			wantSafe: false,
		},
		{
			name:     "empty output with an error must not be treated as empty",
			out:      "",
			err:      errors.New(`exec: "crontab": executable file not found in $PATH`),
			wantSafe: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existing, safe := classifyCrontabList([]byte(tt.out), tt.err)
			if safe != tt.wantSafe {
				t.Errorf("safe = %v, want %v", safe, tt.wantSafe)
			}
			if tt.wantSafe && existing != tt.wantExisting {
				t.Errorf("existing = %q, want %q", existing, tt.wantExisting)
			}
		})
	}
}
