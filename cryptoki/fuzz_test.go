// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"bytes"
	"testing"
)

// FuzzBytesToULong exercises the CK_ULONG decoder against arbitrary-length
// byte slices, the shape a token hands back for a GetAttributeValue call: not
// validated, and not guaranteed to be exactly ULongSize wide. It must never
// panic, must match the documented "truncate past ULongSize, zero-extend
// short" contract, and must round-trip through ULongToBytes.
func FuzzBytesToULong(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0x01})
	f.Add([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x11, 0x22, 0x33})
	f.Add([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x11, 0x22, 0x33, 0xff, 0xff})
	f.Add(ULongToBytes(0))
	f.Add(ULongToBytes(1<<32 - 1))

	f.Fuzz(func(t *testing.T, b []byte) {
		got := BytesToULong(b)

		n := len(b)
		if n > ULongSize {
			n = ULongSize
		}
		if want := leUint(b[:n]); uint64(got) != want {
			t.Fatalf("BytesToULong(%x) = %#x, want %#x", b, got, want)
		}

		if rt := BytesToULong(ULongToBytes(got)); rt != got {
			t.Fatalf("round trip broke: %d -> %x -> %d", got, ULongToBytes(got), rt)
		}
	})
}

// FuzzNewAttributeBytes checks that the []byte branch of NewAttribute always
// stores what it was given, and that the stored Value does not alias the
// caller's slice (NewAttribute's doc comment promises a copy so a later wipe
// or reuse of the caller's buffer can't corrupt the attribute).
func FuzzNewAttributeBytes(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0xde, 0xad, 0xbe, 0xef})

	f.Fuzz(func(t *testing.T, b []byte) {
		a := NewAttribute(CKA_VALUE, b)
		if !bytes.Equal(a.Value, b) {
			t.Fatalf("NewAttribute(%x).Value = %x, want %x", b, a.Value, b)
		}
		if len(b) > 0 {
			want := append([]byte(nil), b...)
			b[0] ^= 0xff // mutate the caller's slice after the call
			if !bytes.Equal(a.Value, want) {
				t.Fatalf("NewAttribute's Value aliases the caller's slice")
			}
		}
	})
}

// FuzzNewAttributeString checks the string branch of NewAttribute round-trips
// arbitrary (including invalid-UTF-8 and NUL-containing) strings unchanged.
func FuzzNewAttributeString(f *testing.F) {
	f.Add("")
	f.Add("hello")
	f.Add("\x00\x01binary-ish")

	f.Fuzz(func(t *testing.T, s string) {
		if got := NewAttribute(CKA_LABEL, s).Value; string(got) != s {
			t.Fatalf("NewAttribute(%q).Value = %q, want %q", s, got, s)
		}
	})
}
