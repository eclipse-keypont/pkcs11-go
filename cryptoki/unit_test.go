// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"bytes"
	"testing"
)

// leUint decodes b as a little-endian unsigned integer (all supported targets
// are little-endian), independent of its width.
func leUint(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

func TestVersionString(t *testing.T) {
	if got := (Version{Major: 3, Minor: 2}).String(); got != "3.2" {
		t.Fatalf("Version.String() = %q, want 3.2", got)
	}
}

func TestNewMechanism(t *testing.T) {
	m := NewMechanism(CKM_SHA256, nil)
	if m.Mechanism != CKM_SHA256 {
		t.Fatalf("Mechanism = %#x, want %#x", m.Mechanism, CKM_SHA256)
	}
	if m.Parameter != nil {
		t.Fatalf("Parameter = %v, want nil", m.Parameter)
	}
}

func TestNewAttributeEncoding(t *testing.T) {
	if got := NewAttribute(CKA_TOKEN, true).Value; !bytes.Equal(got, []byte{1}) {
		t.Fatalf("bool true → %v, want [1]", got)
	}
	if got := NewAttribute(CKA_TOKEN, false).Value; !bytes.Equal(got, []byte{0}) {
		t.Fatalf("bool false → %v, want [0]", got)
	}
	if got := NewAttribute(CKA_LABEL, "hello").Value; string(got) != "hello" {
		t.Fatalf("string → %q, want hello", got)
	}
	raw := []byte{0xde, 0xad, 0xbe, 0xef}
	if got := NewAttribute(CKA_ID, raw).Value; !bytes.Equal(got, raw) {
		t.Fatalf("[]byte → %v, want %v", got, raw)
	}
	if got := NewAttribute(CKA_VALUE, nil).Value; got != nil {
		t.Fatalf("nil → %v, want nil", got)
	}

	// CK_ULONG is platform-sized; check the value round-trips regardless of width.
	a := NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY))
	if l := len(a.Value); l != 4 && l != 8 {
		t.Fatalf("CK_ULONG width = %d, want 4 or 8", l)
	}
	if got := leUint(a.Value); got != uint64(CKO_SECRET_KEY) {
		t.Fatalf("CK_ULONG value = %d, want %d", got, CKO_SECRET_KEY)
	}
}

func TestNewAttributePanicsOnUnsupported(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for unsupported value type")
		}
	}()
	NewAttribute(CKA_VALUE, struct{}{})
}

func TestULongToBytes(t *testing.T) {
	// The encoding is one CK_ULONG wide, no matter the value: a token handed a
	// 4-byte parameter where it expects 8 reads past the end of it.
	for _, v := range []uint{0, 1, 0xff, CKO_SECRET_KEY, CKM_SHA256, 1<<32 - 1} {
		got := ULongToBytes(v)
		if len(got) != ULongSize {
			t.Fatalf("ULongToBytes(%d) is %d bytes, want %d", v, len(got), ULongSize)
		}
		if decoded := leUint(got); decoded != uint64(v) {
			t.Fatalf("ULongToBytes(%d) decodes to %d", v, decoded)
		}
	}
}

func TestULongRoundTrip(t *testing.T) {
	for _, v := range []uint{0, 1, 0xff, 0xddccbbaa, CKO_SECRET_KEY} {
		if got := BytesToULong(ULongToBytes(v)); got != v {
			t.Fatalf("round trip of %d gave %d", v, got)
		}
	}
}

func TestBytesToULongWidths(t *testing.T) {
	// Tokens return CK_ULONG attributes shorter than a CK_ULONG (SoftHSM's
	// 4-byte CKA_PARAMETER_SET) and, occasionally, longer. Neither may read
	// past what the token actually supplied.
	full := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x11, 0x22, 0x33}

	for n := 0; n <= len(full); n++ {
		in := full[:n]

		want := leUint(in)
		if n > ULongSize {
			want = leUint(in[:ULongSize])
		}

		if got := BytesToULong(in); got != uint(want) {
			t.Fatalf("BytesToULong(%X) = %#x, want %#x", in, got, want)
		}
	}

	if got := BytesToULong(nil); got != 0 {
		t.Fatalf("BytesToULong(nil) = %d, want 0", got)
	}

	// Bytes past the first CK_ULONG are ignored, not misread.
	if BytesToULong(full) != BytesToULong(append(append([]byte{}, full...), full...)) {
		t.Fatal("a value longer than a CK_ULONG was not truncated")
	}
}
