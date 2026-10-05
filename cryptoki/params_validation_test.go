// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"testing"
	"unsafe"
)

// TestNewPSSParamsRejectsNegativeSalt checks the signed→unsigned guard (M-P7):
// a negative salt length must panic rather than be converted to a huge
// CK_ULONG and handed to the token.
func TestNewPSSParamsRejectsNegativeSalt(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for negative PSS salt length")
		}
	}()
	NewPSSParams(CKM_SHA256, CKG_MGF1_SHA256, -1)
}

// TestNewPSSParamsAcceptsZeroSalt checks the boundary: a zero salt length is
// valid (PSS with no salt) and must not panic.
func TestNewPSSParamsAcceptsZeroSalt(t *testing.T) {
	p := NewPSSParams(CKM_SHA256, CKG_MGF1_SHA256, 0)
	if p == nil {
		t.Fatal("NewPSSParams(..., 0) returned nil")
	}
}

// TestGCMParamsSizeSane checks the exported struct size matches the OASIS v3.2
// six-field layout: three pointers plus three CK_ULONGs. A different value
// means the vendored header is not the spec struct (P18).
func TestGCMParamsSizeSane(t *testing.T) {
	want := 3*unsafe.Sizeof(uintptr(0)) + 3*ULongSize
	if GCMParamsSize != want {
		t.Fatalf("GCMParamsSize = %d, want %d (3 pointers + 3 CK_ULONG)", GCMParamsSize, want)
	}
}

// TestGCMParamsFreeDefersWhileInUse checks the M-P10 guard: Free called while a
// build() is outstanding must not release the buffers; the release happens when
// the build's cleanup runs.
func TestGCMParamsFreeDefersWhileInUse(t *testing.T) {
	p := NewGCMParams([]byte("0123456789ab"), []byte("aad"), 128)

	_, _, done := p.build() // simulate an in-flight Init

	p.Free() // must defer, not free
	if p.gp == nil {
		t.Fatal("Free released the struct while a build was in flight")
	}
	if !p.freePending {
		t.Fatal("Free did not mark the release as pending")
	}

	done() // build cleanup runs → deferred release happens
	if p.gp != nil {
		t.Fatal("deferred Free did not release the struct after build cleanup")
	}
}

// TestGCMParamsFreeIdempotent checks Free is safe to call repeatedly and after
// the deferred release has already run.
func TestGCMParamsFreeIdempotent(t *testing.T) {
	p := NewGCMParams([]byte("0123456789ab"), nil, 128)
	p.Free()
	p.Free()
	if p.gp != nil {
		t.Fatal("Free left the struct allocated")
	}
}
