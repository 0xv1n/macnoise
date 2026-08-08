package network

import (
	"math/rand"
	"testing"
	"time"
)

// A perfectly fixed beacon interval is trivially fingerprinted, so jitter has
// to actually vary the delay, stay within the requested bound, and never go
// negative.
func TestJitterInterval(t *testing.T) {
	base := 10 * time.Second
	rnd := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic test input

	t.Run("zero jitter is exact", func(t *testing.T) {
		if got := jitterInterval(base, 0, rnd); got != base {
			t.Errorf("jitterInterval(%v, 0) = %v, want %v unchanged", base, got, base)
		}
	})

	t.Run("negative jitter is treated as zero", func(t *testing.T) {
		if got := jitterInterval(base, -20, rnd); got != base {
			t.Errorf("jitterInterval(%v, -20) = %v, want %v unchanged", base, got, base)
		}
	})

	t.Run("stays within the requested bound", func(t *testing.T) {
		const pct = 30
		lo := time.Duration(float64(base) * 0.70)
		hi := time.Duration(float64(base) * 1.30)
		for range 500 {
			got := jitterInterval(base, pct, rnd)
			if got < lo || got > hi {
				t.Fatalf("jitterInterval(%v, %d) = %v, outside [%v, %v]", base, pct, got, lo, hi)
			}
		}
	})

	t.Run("actually varies the delay", func(t *testing.T) {
		seen := map[time.Duration]bool{}
		for range 50 {
			seen[jitterInterval(base, 50, rnd)] = true
		}
		if len(seen) < 2 {
			t.Errorf("jitter produced %d distinct delay(s); the interval is still fixed", len(seen))
		}
	})

	t.Run("over-100 percent does not go negative", func(t *testing.T) {
		for range 500 {
			if got := jitterInterval(base, 400, rnd); got < 0 {
				t.Fatalf("jitterInterval(%v, 400) = %v, want a non-negative delay", base, got)
			}
		}
	})
}
