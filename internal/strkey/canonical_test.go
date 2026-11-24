package strkey

import (
	"bytes"
	"encoding/base32"
	"errors"
	"strings"
	"testing"
)

func decodeNoPad(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

func flipFinalSymbolSpareBit(t *testing.T, s string) string {
	t.Helper()
	last := s[len(s)-1]
	i := strings.IndexByte(independentAlphabet, last)
	if i < 0 {
		t.Fatalf("final symbol %q is not in the base32 alphabet", last)
	}
	return s[:len(s)-1] + string(independentAlphabet[i^1])
}

func TestCanonicalRefusals(t *testing.T) {
	t.Parallel()

	key := encodeStrkey(6, bytes.Repeat([]byte{0x33}, 32))
	if len(key) != 56 {
		t.Fatalf("valid account length = %d, want 56", len(key))
	}
	if _, err := Classify(key); err != nil {
		t.Fatalf("valid unpadded key rejected: %v", err)
	}

	lower := key[:1] + strings.ToLower(key[1:2]) + key[2:]
	for _, tt := range []struct {
		name    string
		input   string
		wantErr error
	}{
		{"one lowercased character", lower, ErrCanonical},
		{"one padding symbol", key + "=", ErrPadding},
		{"two padding symbols", key + "==", ErrPadding},
		{"three padding symbols", key + "===", ErrPadding},
		{"four padding symbols", key + "====", ErrPadding},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Classify(tt.input)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestUnusedBitsInFinalSymbol(t *testing.T) {
	t.Parallel()

	// A 56-character G key fills 35 bytes exactly, so its final symbol has no
	// spare bit. Changing that symbol changes decoded data and cannot exercise
	// the round trip. A 69-character M key leaves one spare bit, which the base32
	// decoder drops before the checksum is read.
	g := encodeStrkey(6, bytes.Repeat([]byte{0x44}, 32))
	gDecoded, err := decodeNoPad(g)
	if err != nil {
		t.Fatalf("decode of G key: %v", err)
	}
	if len(gDecoded) != 35 {
		t.Fatalf("decoded G key length = %d, want 35", len(gDecoded))
	}
	gMutant := flipFinalSymbolSpareBit(t, g)
	gMutantDecoded, err := decodeNoPad(gMutant)
	if err != nil {
		t.Fatalf("decode of mutated G key: %v", err)
	}
	if bytes.Equal(gDecoded, gMutantDecoded) {
		t.Fatal("mutating the G final symbol left decoded bytes unchanged")
	}

	m := sep23Valid[1].s
	if len(m) != 69 {
		t.Fatalf("valid muxed account length = %d, want 69", len(m))
	}
	if _, err := Classify(m); err != nil {
		t.Fatalf("valid muxed account rejected: %v", err)
	}
	mutant := flipFinalSymbolSpareBit(t, m)
	if mutant == m {
		t.Fatal("mutation did not change the final symbol")
	}
	mDecoded, err := decodeNoPad(m)
	if err != nil {
		t.Fatalf("decode of M key: %v", err)
	}
	mutantDecoded, err := decodeNoPad(mutant)
	if err != nil {
		t.Fatalf("decode of mutated M key: %v", err)
	}
	if !bytes.Equal(mDecoded, mutantDecoded) {
		t.Fatal("mutation changed decoded bytes; the spare bit was not the only change")
	}
	if _, err := Classify(mutant); !errors.Is(err, ErrCanonical) {
		t.Fatalf("error = %v, want %v", err, ErrCanonical)
	}
}
