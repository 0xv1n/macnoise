package plistmod

import (
	"errors"
	"testing"
)

// classifyDefaultsRead must never mistake a permission or unexpected read
// failure for "key does not exist": doing so is what let Generate overwrite
// a real user preference without any way to restore it, since Cleanup could
// then only ever delete the key.
func TestClassifyDefaultsRead(t *testing.T) {
	tests := []struct {
		name        string
		out         string
		err         error
		wantSafe    bool
		wantExisted bool
		wantValue   string
	}{
		{
			name:        "existing simple string value",
			out:         "true\n",
			err:         nil,
			wantSafe:    true,
			wantExisted: true,
			wantValue:   "true",
		},
		{
			name:        "existing numeric-looking value",
			out:         "1\n",
			err:         nil,
			wantSafe:    true,
			wantExisted: true,
			wantValue:   "1",
		},
		{
			name:        "key does not exist, short message form",
			out:         "The domain/default pair of (com.macnoise.test, MacnoiseTest) does not exist\n",
			err:         errors.New("exit status 1"),
			wantSafe:    true,
			wantExisted: false,
		},
		{
			name:     "empty output with a generic error must not be treated as absent",
			out:      "",
			err:      errors.New("exit status 1"),
			wantSafe: false,
		},
		{
			name:        "does not exist message with domain/key detail",
			out:         "2026-07-30 12:00:00.000 defaults[1234:5678]\nThe domain/default pair of (com.macnoise.test, MacnoiseTest) does not exist\n",
			err:         errors.New("exit status 1"),
			wantSafe:    true,
			wantExisted: false,
		},
		{
			name:     "array value must not be treated as restorable",
			out:      "(\n    item1,\n    item2\n)\n",
			err:      nil,
			wantSafe: false,
		},
		{
			name:     "dict value must not be treated as restorable",
			out:      "{\n    key1 = val1;\n}\n",
			err:      nil,
			wantSafe: false,
		},
		{
			name:     "permission denied must not be treated as absent",
			out:      "defaults: Could not read domain com.apple.finder; operation not permitted\n",
			err:      errors.New("exit status 1"),
			wantSafe: false,
		},
		{
			name:     "unrecognized error text must not be treated as absent",
			out:      "defaults: some future error we have never seen\n",
			err:      errors.New("exit status 1"),
			wantSafe: false,
		},
		{
			name:     "exec-level failure must not be treated as absent",
			out:      "",
			err:      errors.New(`exec: "defaults": executable file not found in $PATH`),
			wantSafe: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyDefaultsRead([]byte(tt.out), tt.err)
			if got.safe != tt.wantSafe {
				t.Errorf("safe = %v, want %v", got.safe, tt.wantSafe)
			}
			if !tt.wantSafe {
				return
			}
			if got.existed != tt.wantExisted {
				t.Errorf("existed = %v, want %v", got.existed, tt.wantExisted)
			}
			if tt.wantExisted && got.value != tt.wantValue {
				t.Errorf("value = %q, want %q", got.value, tt.wantValue)
			}
		})
	}
}
