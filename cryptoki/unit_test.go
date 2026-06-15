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
