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
	"math"
)

// This file implements the PKCS #11 v3.2 entry points. They are dispatched
// through the module's 3.2 function list, which the loader resolves via
// C_GetInterface (see SupportsV32). On a module that exposes only a 2.x
// interface every method here returns an error wrapping CKR_FUNCTION_NOT_SUPPORTED.

// EncapsulateKey runs a KEM encapsulation (C_EncapsulateKey): it generates a
// fresh shared secret as a key object (described by tmpl) under the public key
// and returns the ciphertext to transmit alongside the new key's handle. Used
// with ML-KEM (CKM_ML_KEM).
func (c *Ctx) EncapsulateKey(sh SessionHandle, m *Mechanism, pubKey ObjectHandle, tmpl []*Attribute) ([]byte, ObjectHandle, error) {
	mod, release, err := c.grab()
	if err != nil {
		return nil, 0, err
	}
	defer release()
	mech, freeMech, err := cMechanism(m)
	if err != nil {
		return nil, 0, err
	}
	defer freeMech()
	arr, n, freeAttrs, err := cAttributes(tmpl)
	if err != nil {
		return nil, 0, err
	}
	defer freeAttrs()

	// Sizing pass: a NULL ciphertext buffer asks only for the length and does
	// not create the key.
	var ctLen C.CK_ULONG
	var key C.CK_OBJECT_HANDLE
	rv := C.ck_encapsulate_key(mod, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(pubKey), arr, n, nil, &ctLen, &key)
	if err := toError(uint(rv)); err != nil {
		return nil, 0, err
	}

	// A KEM ciphertext is never empty. A zero length would also leave the
	// data pass with a NULL buffer, which asks for the length again instead
	// of encapsulating.
	if ctLen == 0 {
		return nil, 0, fmt.Errorf("cryptoki: EncapsulateKey: module reported an empty ciphertext")
	}
	// ctLen is module-reported. Bound it by maxOutBuf (as outOp does) and by
	// the C.int range C.GoBytes accepts, so a bogus length cannot drive an
	// unbounded allocation or a mis-sized copy.
	if uint64(ctLen) > maxOutBuf {
		return nil, 0, fmt.Errorf("cryptoki: EncapsulateKey: ciphertext size %d exceeds limit %d", uint64(ctLen), uint64(maxOutBuf))
	}
	if uint64(ctLen) > math.MaxInt32 {
		return nil, 0, fmt.Errorf("cryptoki: EncapsulateKey: ciphertext size %d exceeds C.int range", uint64(ctLen))
	}
	// allocLen is the capacity of buf. Keep it apart from ctLen, which the data
	// pass overwrites with whatever length the module reports.
	allocLen := ctLen
	buf := cMalloc(ctLen)
	defer C.free(buf)
	rv = C.ck_encapsulate_key(mod, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(pubKey), arr, n, (C.CK_BYTE_PTR)(buf), &ctLen, &key)
	if err := toError(uint(rv)); err != nil {
		return nil, 0, err
	}
	// A successful data pass must report a ciphertext that fits the buffer it
	// was given, and is not empty, and a key; C.GoBytes would otherwise read
	// past the allocation. The module may already have created the key, so
	// destroy it rather than hand back an orphan.
	if ctLen == 0 || ctLen > allocLen || key == C.CK_INVALID_HANDLE {
		if key != C.CK_INVALID_HANDLE {
			_ = C.ck_destroy_object(mod, C.CK_SESSION_HANDLE(sh), key)
		}
		return nil, 0, fmt.Errorf("cryptoki: EncapsulateKey: module reported ciphertext size %d for a %d-byte buffer, and key handle %d",
			uint64(ctLen), uint64(allocLen), uint64(key))
	}
	return C.GoBytes(buf, C.int(ctLen)), ObjectHandle(key), nil
}

// DecapsulateKey runs a KEM decapsulation (C_DecapsulateKey): it recovers the
// shared secret from ciphertext using the private key, materialising it as a
// new key object (described by tmpl) and returning its handle. Used with
// ML-KEM (CKM_ML_KEM).
func (c *Ctx) DecapsulateKey(sh SessionHandle, m *Mechanism, privKey ObjectHandle, tmpl []*Attribute, ciphertext []byte) (ObjectHandle, error) {
	mod, release, err := c.grab()
	if err != nil {
		return 0, err
	}
	defer release()
	mech, freeMech, err := cMechanism(m)
	if err != nil {
		return 0, err
	}
	defer freeMech()
	arr, n, freeAttrs, err := cAttributes(tmpl)
	if err != nil {
		return 0, err
	}
	defer freeAttrs()
	ct, ctLen := cInput(ciphertext)
	defer free(ct)

	var key C.CK_OBJECT_HANDLE
	rv := C.ck_decapsulate_key(mod, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(privKey), arr, n, (C.CK_BYTE_PTR)(ct), ctLen, &key)
	if err := toError(uint(rv)); err != nil {
		return 0, err
	}
	return ObjectHandle(key), nil
}

// VerifySignatureInit begins a stateless signature verification against a known
// signature value (C_VerifySignatureInit). Unlike VerifyInit, the signature is
// supplied up front; VerifySignature then only takes the data.
func (c *Ctx) VerifySignatureInit(sh SessionHandle, m *Mechanism, key ObjectHandle, signature []byte) error {
	mod, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	mech, freeMech, err := cMechanism(m)
	if err != nil {
		return err
	}
	defer freeMech()
	sig, sn := cInput(signature)
	defer free(sig)
	rv := C.ck_verify_signature_init(mod, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(key), (C.CK_BYTE_PTR)(sig), sn)
	return toError(uint(rv))
}

// VerifySignature checks the data against the signature given to
// VerifySignatureInit, in a single part (C_VerifySignature). A nil error means
// valid.
func (c *Ctx) VerifySignature(sh SessionHandle, data []byte) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	p, n := cInput(data)
	defer zfree(p, n)
	return toError(uint(C.ck_verify_signature(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n)))
}

// VerifySignatureUpdate feeds another part of the data into a multi-part
// stateless verification (C_VerifySignatureUpdate).
func (c *Ctx) VerifySignatureUpdate(sh SessionHandle, part []byte) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	p, n := cInput(part)
	defer zfree(p, n)
	return toError(uint(C.ck_verify_signature_update(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n)))
}

// VerifySignatureFinal finishes a multi-part stateless verification
// (C_VerifySignatureFinal). A nil error means valid.
func (c *Ctx) VerifySignatureFinal(sh SessionHandle) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	return toError(uint(C.ck_verify_signature_final(m, C.CK_SESSION_HANDLE(sh))))
}

// GetSessionValidationFlags returns the FIPS-style validation flags for a
// session (C_GetSessionValidationFlags). flagType selects which set of flags.
func (c *Ctx) GetSessionValidationFlags(sh SessionHandle, flagType uint) (uint, error) {
	m, release, err := c.grab()
	if err != nil {
		return 0, err
	}
	defer release()
	var flags C.CK_FLAGS
	rv := C.ck_get_session_validation_flags(m, C.CK_SESSION_HANDLE(sh),
		C.CK_SESSION_VALIDATION_FLAGS_TYPE(flagType), &flags)
	if err := toError(uint(rv)); err != nil {
		return 0, err
	}
	return uint(flags), nil
}

// SessionCancel ends the active operations on a session that flags names
// (C_SessionCancel): CKF_ENCRYPT, CKF_DECRYPT, CKF_DIGEST, CKF_SIGN, CKF_VERIFY
// and the other operation flags, OR-ed together. It is a v3.0 function, so it
// needs a module with a v3.2 interface, and a module may still answer
// CKR_FUNCTION_NOT_SUPPORTED.
func (c *Ctx) SessionCancel(sh SessionHandle, flags uint) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	return toError(uint(C.ck_session_cancel(m, C.CK_SESSION_HANDLE(sh), C.CK_FLAGS(flags))))
}

// WrapKeyAuthenticated wraps a key with an AEAD wrapping mechanism, binding the
// given associated data, and returns the wrapped bytes (C_WrapKeyAuthenticated).
func (c *Ctx) WrapKeyAuthenticated(sh SessionHandle, m *Mechanism, wrappingKey, key ObjectHandle, aad []byte) ([]byte, error) {
	mod, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	mech, freeMech, err := cMechanism(m)
	if err != nil {
		return nil, err
	}
	defer freeMech()
	ad, adLen := cInput(aad)
	defer free(ad)
	return outOp(nil, func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_wrap_key_authenticated(mod, C.CK_SESSION_HANDLE(sh), mech,
			C.CK_OBJECT_HANDLE(wrappingKey), C.CK_OBJECT_HANDLE(key),
			(C.CK_BYTE_PTR)(ad), adLen, out, outLen)
	})
}

// UnwrapKeyAuthenticated unwraps a key produced by WrapKeyAuthenticated,
// verifying the associated data, into a new object described by the template
// (C_UnwrapKeyAuthenticated).
func (c *Ctx) UnwrapKeyAuthenticated(sh SessionHandle, m *Mechanism, unwrappingKey ObjectHandle, wrapped, aad []byte, tmpl []*Attribute) (ObjectHandle, error) {
	mod, release, err := c.grab()
	if err != nil {
		return 0, err
	}
	defer release()
	mech, freeMech, err := cMechanism(m)
	if err != nil {
		return 0, err
	}
	defer freeMech()
	wp, wn := cInput(wrapped)
	defer free(wp)
	ad, adLen := cInput(aad)
	defer free(ad)
	arr, n, freeAttrs, err := cAttributes(tmpl)
	if err != nil {
		return 0, err
	}
	defer freeAttrs()

	var key C.CK_OBJECT_HANDLE
	rv := C.ck_unwrap_key_authenticated(mod, C.CK_SESSION_HANDLE(sh), mech,
		C.CK_OBJECT_HANDLE(unwrappingKey), (C.CK_BYTE_PTR)(wp), wn, arr, n,
		(C.CK_BYTE_PTR)(ad), adLen, &key)
	if err := toError(uint(rv)); err != nil {
		return 0, err
	}
	return ObjectHandle(key), nil
}
