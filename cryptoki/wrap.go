// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include "shim.h"
*/
import "C"

// WrapKey wraps (encrypts) a key with a wrapping key and returns the wrapped
// bytes (C_WrapKey).
func (c *Ctx) WrapKey(sh SessionHandle, m *Mechanism, wrappingKey, key ObjectHandle) ([]byte, error) {
	mod, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	mech, freeMech := cMechanism(m)
	defer freeMech()
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_wrap_key(mod, C.CK_SESSION_HANDLE(sh), mech,
			C.CK_OBJECT_HANDLE(wrappingKey), C.CK_OBJECT_HANDLE(key), out, outLen)
	})
}

// UnwrapKey unwraps (decrypts) a previously wrapped key into a new object
// described by the template, returning its handle (C_UnwrapKey).
func (c *Ctx) UnwrapKey(sh SessionHandle, m *Mechanism, unwrappingKey ObjectHandle, wrapped []byte, tmpl []*Attribute) (ObjectHandle, error) {
	mod, release, err := c.grab()
	if err != nil {
		return 0, err
	}
	defer release()
	mech, freeMech := cMechanism(m)
	defer freeMech()
	wp, wn := cBytes(wrapped)
	defer free(wp)
	arr, n, freeAttrs := cAttributes(tmpl)
	defer freeAttrs()

	var key C.CK_OBJECT_HANDLE
	rv := C.ck_unwrap_key(mod, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(unwrappingKey), (C.CK_BYTE_PTR)(wp), wn, arr, n, &key)
	if err := toError(uint(rv)); err != nil {
		return 0, err
	}
	return ObjectHandle(key), nil
}

// DeriveKey derives a new key from a base key per the mechanism and template,
// returning its handle (C_DeriveKey), e.g. an HKDF or ECDH derivation.
func (c *Ctx) DeriveKey(sh SessionHandle, m *Mechanism, baseKey ObjectHandle, tmpl []*Attribute) (ObjectHandle, error) {
	mod, release, err := c.grab()
	if err != nil {
		return 0, err
	}
	defer release()
	mech, freeMech := cMechanism(m)
	defer freeMech()
	arr, n, freeAttrs := cAttributes(tmpl)
	defer freeAttrs()

	var key C.CK_OBJECT_HANDLE
	rv := C.ck_derive_key(mod, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(baseKey), arr, n, &key)
	if err := toError(uint(rv)); err != nil {
		return 0, err
	}
	return ObjectHandle(key), nil
}
