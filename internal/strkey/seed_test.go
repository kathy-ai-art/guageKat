package strkey

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"strings"
	"testing"
)

func seedFromFragments(fill byte) string {
	parts := []string{"S", encodeStrkey(18, bytes.Repeat([]byte{fill}, 32))[1:]}
	return strings.Join(parts, "")
}

func checksumCorruptedSeed(t *testing.T, seed string) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(seed)
	if err != nil {
		t.Fatalf("decode of seed fragments: %v", err)
	}
	raw[len(raw)-2] ^= 0x01
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}

func errorEchoesInput(err error, input string) bool {
	if err == nil {
		return false
	}
	for _, format := range []string{"%v", "%+v", "%s"} {
		printed := fmt.Sprintf(format, err)
		if strings.Contains(printed, input) {
			return true
		}
		for i := 0; i+8 <= len(input); i++ {
			if strings.Contains(printed, input[i:i+8]) {
				return true
			}
		}
	}
	return false
}

func TestSeedFromFragments(t *testing.T) {
	t.Parallel()

	seed := seedFromFragments(0x5C)
	kind, err := Classify(seed)
	if err != nil {
		t.Fatalf("well-formed seed fragments rejected: %v", err)
	}
	if kind != Seed {
		t.Fatalf("kind = %q, want %q", kind, Seed)
	}
	if !IsSeed(seed) {
		t.Fatal("well-formed seed fragments were not detected")
	}
}

func TestIsSeedRejectsNonCanonicalForms(t *testing.T) {
	t.Parallel()

	seed := seedFromFragments(0x6D)
	for _, tt := range []struct {
		name  string
		input string
	}{
		{"one character truncation", seed[:len(seed)-1]},
		{"checksum byte changed at a valid length", checksumCorruptedSeed(t, seed)},
		{"lowercase seed", strings.ToLower(seed)},
		{"stray padding", seed + "="},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if IsSeed(tt.input) {
				t.Fatalf("%s reported as a seed", tt.name)
			}
			_, err := Classify(tt.input)
			if err == nil {
				t.Fatalf("%s accepted", tt.name)
			}
			if errorEchoesInput(err, tt.input) {
				t.Fatalf("%s produced an error that echoed the rejected input", tt.name)
			}
		})
	}
}

func TestNoEchoDetectorCatchesLeakingError(t *testing.T) {
	t.Parallel()

	seed := seedFromFragments(0x7E)
	if !errorEchoesInput(fmt.Errorf("sentinel: %s", seed), seed) {
		t.Fatal("detector missed an error carrying the input")
	}
}
