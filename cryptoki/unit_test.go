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

func TestAttributeName(t *testing.T) {
	cases := []struct {
		typ  uint
		want string
	}{
		{CKA_CLASS, "CKA_CLASS"},
		{CKA_LABEL, "CKA_LABEL"},
		{CKA_WRAP_TEMPLATE, "CKA_WRAP_TEMPLATE"},
		{CKA_SEED, "CKA_SEED"},
		{CKA_VENDOR_DEFINED, "CKA_VENDOR_DEFINED"},
		// Values with two header names report the current one.
		{CKA_ECDSA_PARAMS, "CKA_EC_PARAMS"},
		{CKA_SUB_PRIME_BITS, "CKA_SUBPRIME_BITS"},
		// Types the header does not name are rendered as hex.
		{CKA_VENDOR_DEFINED | 1, "0x80000001"},
		{0x00000999, "0x00000999"},
	}
	for _, c := range cases {
		if got := AttributeName(c.typ); got != c.want {
			t.Errorf("AttributeName(%#x) = %q, want %q", c.typ, got, c.want)
		}
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

// TestInfoULong checks that CK_UNAVAILABLE_INFORMATION written by the module
// compares equal to the Go constant, at this platform's CK_ULONG width and at
// the 32-bit width of Windows' LLP64 model.
func TestInfoULong(t *testing.T) {
	if got := infoULong(ulongUnavailable); got != CK_UNAVAILABLE_INFORMATION {
		t.Fatalf("infoULong(native ~0) = %#x, want CK_UNAVAILABLE_INFORMATION", got)
	}
	if got := infoULong(42); got != 42 {
		t.Fatalf("infoULong(42) = %d, want 42", got)
	}
	if got := infoULong(CK_EFFECTIVELY_INFINITE); got != CK_EFFECTIVELY_INFINITE {
		t.Fatalf("infoULong(CK_EFFECTIVELY_INFINITE) = %#x, want it unchanged", got)
	}

	saved := ulongUnavailable
	ulongUnavailable = 0xFFFFFFFF // a 32-bit CK_ULONG
	defer func() { ulongUnavailable = saved }()
	if got := infoULong(0xFFFFFFFF); got != CK_UNAVAILABLE_INFORMATION {
		t.Fatalf("infoULong(32-bit ~0) = %#x, want CK_UNAVAILABLE_INFORMATION", got)
	}
}

// templateTypes are the attribute types whose value is a nested template.
// The last is a vendor-defined array attribute, which counts as one.
var templateTypes = []uint{
	CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE,
	CKA_ENCAPSULATE_TEMPLATE, CKA_DECAPSULATE_TEMPLATE,
	CKA_VENDOR_DEFINED | CKF_ARRAY_ATTRIBUTE | 1,
}

func TestIsTemplateAttribute(t *testing.T) {
	for _, typ := range templateTypes {
		if !isTemplateAttribute(typ) {
			t.Errorf("isTemplateAttribute(%s) = false, want true", AttributeName(typ))
		}
	}
	for _, typ := range []uint{
		CKA_CLASS, CKA_VALUE, CKA_LABEL, CKA_ENCAPSULATE, CKA_DECAPSULATE,
		CKA_ALLOWED_MECHANISMS,
	} {
		if isTemplateAttribute(typ) {
			t.Errorf("isTemplateAttribute(%s) = true, want false", AttributeName(typ))
		}
	}
}

// TestCAttributesRefusesNestedTemplates checks that a template attribute
// never reaches a module as raw bytes, which it would read as CK_ATTRIBUTE
// structures holding pointers, and that a nil entry is an error rather than a
// panic. CKA_ALLOWED_MECHANISMS, a flat array, still goes through.
func TestCAttributesRefusesNestedTemplates(t *testing.T) {
	for _, typ := range templateTypes {
		_, _, _, err := cAttributes([]*Attribute{
			NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
			NewAttribute(typ, make([]byte, 64)),
		})
		if err == nil {
			t.Errorf("cAttributes accepted %s", AttributeName(typ))
		}
	}
	if _, _, _, err := cAttributes([]*Attribute{NewAttribute(CKA_TOKEN, false), nil}); err == nil {
		t.Error("cAttributes accepted a nil entry")
	}
	_, _, freeAttrs, err := cAttributes([]*Attribute{
		NewAttribute(CKA_ALLOWED_MECHANISMS, append(ckULong(CKM_AES_GCM), ckULong(CKM_AES_CBC_PAD)...)),
	})
	if err != nil {
		t.Fatalf("cAttributes(CKA_ALLOWED_MECHANISMS): %v", err)
	}
	freeAttrs()
}
