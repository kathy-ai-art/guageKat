package model

import (
	"math/rand"
	"testing"
)

func TestSortTiebreakShuffleIsIdentical(t *testing.T) {
	t.Parallel()
	findings := []Finding{
		NewFinding("sig-a", SevHigh, "acct-a", "m1", "evidence alpha"),
		NewFinding("sig-a", SevHigh, "acct-a", "m2", "evidence beta"),
		NewFinding("sig-a", SevHigh, "acct-a", "m3", "evidence gamma"),
		NewFinding("sig-a", SevHigh, "acct-a", "m4", "evidence delta"),
	}

	want := make([]Finding, len(findings))
	copy(want, findings)
	SortFindings(want)

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 50; i++ {
		shuffled := make([]Finding, len(findings))
		copy(shuffled, findings)
		rng.Shuffle(len(shuffled), func(a, b int) {
			shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
		})
		SortFindings(shuffled)
		for j := range shuffled {
			if shuffled[j].Fingerprint != want[j].Fingerprint {
				t.Fatalf("shuffle %d position %d = %s, want %s", i, j, shuffled[j].Fingerprint, want[j].Fingerprint)
			}
		}
	}
}
