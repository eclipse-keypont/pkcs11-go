// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"testing"
)

// TestCMallocNonNil checks the NULL-checking allocator returns usable memory
// for a normal request. The failure path (C.malloc returning NULL) cannot be
// triggered portably, so only the success contract is asserted here.
func TestCMallocNonNil(t *testing.T) {
	p := cMalloc(16)
	if p == nil {
		t.Fatal("cMalloc(16) returned nil")
	}
	free(p)
}

// TestCAttributesNormalTemplate checks the common path still builds the array
// and reports the right element count after the overflow guard was added.
func TestCAttributesNormalTemplate(t *testing.T) {
	tmpl := []*Attribute{
		NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
		NewAttribute(CKA_LABEL, "k"),
	}
	arr, n, freeAttrs := cAttributes(tmpl)
	defer freeAttrs()
	if arr == nil {
		t.Fatal("cAttributes returned nil array for a non-empty template")
	}
	if uint(n) != uint(len(tmpl)) {
		t.Fatalf("cAttributes count = %d, want %d", uint(n), len(tmpl))
	}
}

// TestCAttributesEmptyTemplate checks the empty template short-circuit.
func TestCAttributesEmptyTemplate(t *testing.T) {
	arr, n, freeAttrs := cAttributes(nil)
	defer freeAttrs()
	if arr != nil || n != 0 {
		t.Fatalf("cAttributes(nil) = (%v, %d), want (nil, 0)", arr, n)
	}
}

// TestCAttributesFits exercises the pure overflow predicate behind
// cAttributes' guard (CWE-190): a count whose n * elemSize would exceed
// maxOutBuf must be rejected, and the boundary must be exact.
func TestCAttributesFits(t *testing.T) {
	const elem = 24 // representative sizeof(CK_ATTRIBUTE)
	limit := int(uint64(maxOutBuf) / uint64(elem))

	if !cAttributesFits(limit, elem) {
		t.Fatalf("cAttributesFits(%d, %d) = false, want true (boundary)", limit, elem)
	}
	if cAttributesFits(limit+1, elem) {
		t.Fatalf("cAttributesFits(%d, %d) = true, want false (one past boundary)", limit+1, elem)
	}
	if cAttributesFits(-1, elem) {
		t.Fatal("cAttributesFits(-1, ...) = true, want false")
	}
	if cAttributesFits(1, 0) {
		t.Fatal("cAttributesFits(1, 0) = true, want false (zero element size)")
	}
	if !cAttributesFits(0, elem) {
		t.Fatal("cAttributesFits(0, ...) = false, want true")
	}
}

// TestMaxListLenSane is a guard-rail on the list bound: it must be positive and
// small enough to be a meaningful cap, yet far above any real token's counts.
func TestMaxListLenSane(t *testing.T) {
	if maxListLen <= 0 {
		t.Fatalf("maxListLen = %d, want positive", maxListLen)
	}
	if maxListLen > 1<<24 {
		t.Fatalf("maxListLen = %d, unexpectedly large", maxListLen)
	}
}
