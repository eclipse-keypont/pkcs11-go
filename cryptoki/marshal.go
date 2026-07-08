// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// This file holds the cgo marshalling helpers shared by the operation methods:
// copying Go bytes into C heap memory, building the CK_ATTRIBUTE and
// CK_MECHANISM structures Cryptoki expects, and reading results back. Every
// allocation returns a free func the caller must defer.

const (
	maxOutBuf  = 64 << 20 // 64 MiB per output operation
	maxRetries = 8        // maximum CKR_BUFFER_TOO_SMALL retries in outOp
)

// cBytes copies b into C heap memory and returns the pointer and its length.
// For an empty slice it returns (nil, 0). The caller frees the pointer (free is
// a no-op on nil; use zfree when the bytes are secret).
func cBytes(b []byte) (unsafe.Pointer, C.CK_ULONG) {
	if len(b) == 0 {
		return nil, 0
	}
	return C.CBytes(b), C.CK_ULONG(len(b))
}

// zfree scrubs n bytes at p (defeating dead-store elimination) and frees it.
// It is a no-op on a nil pointer. Use it instead of free for any C buffer that
// held secret material: a PIN, plaintext, key bytes, or a sensitive attribute.
func zfree(p unsafe.Pointer, n C.CK_ULONG) {
	if p == nil {
		return
	}
	if n > 0 {
		C.ck_memzero(p, n)
	}
	C.free(p)
}

// ckULong encodes v as the platform's native CK_ULONG bytes. The width of
// CK_ULONG differs by platform (8 bytes on most Unix, 4 on Windows), so this
// must go through the C type rather than assuming a fixed size. It panics if v
// does not fit the platform's CK_ULONG (e.g. a value >= 2^32 on Windows),
// turning silent truncation into a visible programming error.
func ckULong(v uint) []byte {
	cv := C.CK_ULONG(v)
	if uint(cv) != v {
		panic("cryptoki: value overflows CK_ULONG on this platform")
	}
	return C.GoBytes(unsafe.Pointer(&cv), C.int(unsafe.Sizeof(cv)))
}

// ckBBool encodes a Cryptoki CK_BBOOL (one byte: CK_TRUE or CK_FALSE).
func ckBBool(b bool) []byte {
	if b {
		return []byte{1}
	}
	return []byte{0}
}

// cMechanism builds a CK_MECHANISM from m and returns a pointer plus a free
// func. A nil m yields a nil pointer (for calls that take no mechanism).
//
// A structured parameter (m.params) is marshalled into C memory by its build
// method, which also owns the cleanup of any nested pointers; otherwise the raw
// Parameter bytes are copied. Either way the returned free releases everything.
func cMechanism(m *Mechanism) (C.CK_MECHANISM_PTR, func()) {
	if m == nil {
		return nil, func() {}
	}
	mech := (*C.CK_MECHANISM)(C.malloc(C.size_t(unsafe.Sizeof(C.CK_MECHANISM{}))))
	mech.mechanism = C.CK_MECHANISM_TYPE(m.Mechanism)

	if m.params != nil {
		ptr, plen, freeParam := m.params.build()
		mech.pParameter = C.CK_VOID_PTR(ptr)
		mech.ulParameterLen = plen
		return mech, func() {
			freeParam()
			C.free(unsafe.Pointer(mech))
		}
	}

	param, plen := cBytes(m.Parameter)
	mech.pParameter = C.CK_VOID_PTR(param)
	mech.ulParameterLen = plen
	return mech, func() {
		// A mechanism parameter may carry sensitive values (e.g. an IV); scrub it.
		zfree(param, plen)
		C.free(unsafe.Pointer(mech))
	}
}

// cAttributes builds a C array of CK_ATTRIBUTE from a Go template and returns
// the pointer, the element count, and a free func. An empty template yields a
// nil pointer with count 0. The free func scrubs every value buffer before
// releasing it, because a template can carry key material (e.g. CKA_VALUE on
// C_CreateObject / C_UnwrapKey).
func cAttributes(tmpl []*Attribute) (C.CK_ATTRIBUTE_PTR, C.CK_ULONG, func()) {
	n := len(tmpl)
	if n == 0 {
		return nil, 0, func() {}
	}
	arr := (*C.CK_ATTRIBUTE)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.CK_ATTRIBUTE{}))))
	list := unsafe.Slice(arr, n)
	type buf struct {
		p unsafe.Pointer
		n C.CK_ULONG
	}
	values := make([]buf, 0, n)
	for i, a := range tmpl {
		list[i]._type = C.CK_ATTRIBUTE_TYPE(a.Type)
		p, l := cBytes(a.Value)
		if p != nil {
			values = append(values, buf{p, l})
		}
		list[i].pValue = C.CK_VOID_PTR(p)
		list[i].ulValueLen = l
	}
	return arr, C.CK_ULONG(n), func() {
		for _, b := range values {
			zfree(b.p, b.n)
		}
		C.free(unsafe.Pointer(arr))
	}
}

// outOp runs a Cryptoki call that writes a variable-length byte result using
// the standard two-pass length convention: call once with a NULL buffer to
// learn the size, allocate, then call again. call receives the output buffer
// (nil on the sizing pass) and a pointer to the length.
//
// If the data pass reports CKR_BUFFER_TOO_SMALL — which a module is permitted
// to do when the precise size only becomes known on the second call — the
// length out-parameter has been updated to the required size, so we reallocate
// and retry rather than failing the operation. The result buffer is scrubbed
// before being freed, since for Decrypt/DecryptFinal it holds plaintext.
// Retries are bounded by maxRetries and the buffer size by maxOutBuf.
func outOp(call func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV) ([]byte, error) {
	var n C.CK_ULONG
	if err := toError(uint(call(nil, &n))); err != nil {
		return nil, err
	}
	for retries := 0; retries < maxRetries; retries++ {
		if n == 0 {
			return []byte{}, nil
		}
		if uint64(n) > maxOutBuf {
			return nil, fmt.Errorf("cryptoki: output size %d exceeds limit %d", uint64(n), uint64(maxOutBuf))
		}
		buf := C.malloc(n)
		rv := uint(call((C.CK_BYTE_PTR)(buf), &n))
		if rv == CKR_BUFFER_TOO_SMALL {
			// n now holds the larger required size; reallocate and retry.
			C.free(buf)
			continue
		}
		if err := toError(rv); err != nil {
			zfree(buf, n)
			return nil, err
		}
		out := C.GoBytes(buf, C.int(n))
		zfree(buf, n)
		return out, nil
	}
	return nil, fmt.Errorf("cryptoki: outOp: CKR_BUFFER_TOO_SMALL after %d retries", maxRetries)
}
