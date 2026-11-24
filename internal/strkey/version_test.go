package strkey

import (
	"bytes"
	"errors"
	"testing"
)

// This file deliberately carries its own CRC16 and base32 encoder. It never
// calls encodeStrkey, encodeRaw or checksum16, so a shared bug cannot cancel
// out between the encoder that builds a vector and the decoder under test.

const independentAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

func independentCRC16(data []byte) uint16 {
	var table [256]uint16
	for i := 0; i < len(table); i++ {
		crc := uint16(i) << 8
		for j := 0; j < 8; j++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
		table[i] = crc
	}
	var crc uint16
	for _, b := range data {
		crc = crc<<8 ^ table[byte(crc>>8)^b]
	}
	return crc
}

func independentBase32(raw []byte) string {
	var out bytes.Buffer
	acc := 0
	bits := 0
	for _, b := range raw {
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(independentAlphabet[(acc>>bits)&31])
			acc &= (1 << bits) - 1
		}
	}
	if bits > 0 {
		out.WriteByte(independentAlphabet[(acc<<(5-bits))&31])
	}
	return out.String()
}

func independentRaw(raw []byte) string {
	buf := append([]byte{}, raw...)
	sum := independentCRC16(buf)
	buf = append(buf, byte(sum), byte(sum>>8))
	return independentBase32(buf)
}

func independentStrkey(version byte, body []byte) string {
	raw := append([]byte{version << 3}, body...)
	return independentRaw(raw)
}

func TestVersionByteBoundaries(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0xA5}, 32)
	mux := append(append([]byte{}, key...), bytes.Repeat([]byte{0x11}, 8)...)
	balance := append([]byte{0}, key...)
	payload := append(append([]byte{}, key...), 0, 0, 0, 32)
	payload = append(payload, bytes.Repeat([]byte{0x5A}, 32)...)

	cases := []struct {
		name    string
		version byte
		kind    Kind
		body    []byte
		short   []byte
		long    []byte
	}{
		{"version 1 claimable balance", 1, ClaimableBalance, balance, balance[:32], append(append([]byte{}, balance...), 0)},
		{"version 2 contract", 2, Contract, key, key[:31], append(append([]byte{}, key...), 0)},
		{"version 6 account", 6, AccountID, key, key[:31], append(append([]byte{}, key...), 0)},
		{"version 11 liquidity pool", 11, LiquidityPool, key, key[:31], append(append([]byte{}, key...), 0)},
		{"version 12 muxed account", 12, MuxedAccount, mux, mux[:39], append(append([]byte{}, mux...), 0)},
		{"version 15 signed payload", 15, SignedPayload, payload, payload[:67], append(append([]byte{}, payload...), 0)},
		{"version 18 seed", 18, Seed, key, key[:31], append(append([]byte{}, key...), 0)},
		{"version 19 pre-auth tx", 19, PreAuthTx, key, key[:31], append(append([]byte{}, key...), 0)},
		{"version 22 muxed contract", 22, MuxedContract, mux, mux[:39], append(append([]byte{}, mux...), 0)},
		{"version 23 hash x", 23, HashX, key, key[:31], append(append([]byte{}, key...), 0)},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			kind, err := Classify(independentStrkey(tt.version, tt.body))
			if err != nil {
				t.Fatalf("valid boundary rejected: %v", err)
			}
			if kind != tt.kind {
				t.Fatalf("kind = %q, want %q", kind, tt.kind)
			}
			for _, side := range []struct {
				name string
				body []byte
			}{
				{"one byte short", tt.short},
				{"one byte long", tt.long},
			} {
				t.Run(side.name, func(t *testing.T) {
					_, err := Classify(independentStrkey(tt.version, side.body))
					if !errors.Is(err, ErrPayload) {
						t.Fatalf("error = %v, want %v", err, ErrPayload)
					}
				})
			}
		})
	}
}

func TestVersionShapeRefusals(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{0xA5}, 32)
	badPad := append(append([]byte{}, key...), 0, 0, 0, 1, 0x7B, 0, 0, 0)
	badPad[37] = 1
	zeroPrefix := append(append([]byte{}, key...), 0, 0, 0, 0, 0, 0, 0, 0)
	overlongPrefix := append(append([]byte{}, key...), 0, 0, 0, 33, 0, 0, 0, 0)

	for _, tt := range []struct {
		name    string
		version byte
		body    []byte
		wantErr error
	}{
		{"claimable balance type one", 1, append([]byte{1}, key...), ErrPayload},
		{"signed payload nonzero pad", 15, badPad, ErrPayload},
		{"signed payload zero prefix", 15, zeroPrefix, ErrPayload},
		{"signed payload overlong prefix", 15, overlongPrefix, ErrPayload},
		{"unknown version", 0, key, ErrVersion},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Classify(independentStrkey(tt.version, tt.body))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}

	t.Run("nonzero algorithm specifier", func(t *testing.T) {
		raw := append([]byte{6<<3 | 1}, key...)
		_, err := Classify(independentRaw(raw))
		if !errors.Is(err, ErrSpecifier) {
			t.Fatalf("error = %v, want %v", err, ErrSpecifier)
		}
	})

	t.Run("recomputed checksum mutation", func(t *testing.T) {
		body := append([]byte{1}, key...)
		s := independentStrkey(1, body)
		_, err := Classify(s)
		if !errors.Is(err, ErrPayload) {
			t.Fatalf("error = %v, want %v", err, ErrPayload)
		}
	})
}
