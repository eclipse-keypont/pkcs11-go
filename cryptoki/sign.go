// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"

// SignInit initialises a signature operation with a private key (C_SignInit).
func (c *Ctx) SignInit(sh SessionHandle, m *Mechanism, key ObjectHandle) error {
	mod, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	mech, freeMech := cMechanism(m)
	defer freeMech()
	return toError(uint(C.ck_sign_init(mod, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(key))))
}

// Sign signs data in a single part and returns the signature (C_Sign).
func (c *Ctx) Sign(sh SessionHandle, data []byte) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	p, n := cBytes(data)
	defer zfree(p, n)
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_sign(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n, out, outLen)
	})
}

// SignUpdate feeds another part of the message into a multi-part signature
// (C_SignUpdate).
func (c *Ctx) SignUpdate(sh SessionHandle, part []byte) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	if len(part) == 0 {
		// Some PKCS#11 implementations (e.g. SoftHSM2) reject a NULL pPart
		// pointer even when ulPartLen is 0. Allocate a 1-byte dummy buffer so
		// the pointer is valid while still signalling zero-length input.
		dummy := C.malloc(1)
		defer C.free(dummy)
		return toError(uint(C.ck_sign_update(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(dummy), 0)))
	}
	p, n := cBytes(part)
	defer zfree(p, n)
	return toError(uint(C.ck_sign_update(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n)))
}

// SignFinal finishes a multi-part signature and returns the signature
// (C_SignFinal).
func (c *Ctx) SignFinal(sh SessionHandle) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_sign_final(m, C.CK_SESSION_HANDLE(sh), out, outLen)
	})
}

// VerifyInit initialises a verification operation with a public key
// (C_VerifyInit).
func (c *Ctx) VerifyInit(sh SessionHandle, m *Mechanism, key ObjectHandle) error {
	mod, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	mech, freeMech := cMechanism(m)
	defer freeMech()
	return toError(uint(C.ck_verify_init(mod, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(key))))
}

// Verify checks a signature over data in a single part (C_Verify). A nil error
// means the signature is valid; an invalid signature reports CKR_SIGNATURE_*.
func (c *Ctx) Verify(sh SessionHandle, data, signature []byte) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	p, n := cBytes(data)
	defer zfree(p, n)
	sig, sn := cBytes(signature)
	defer free(sig)
	rv := C.ck_verify(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n, (C.CK_BYTE_PTR)(sig), sn)
	return toError(uint(rv))
}

// VerifyUpdate feeds another part of the message into a multi-part verification
// (C_VerifyUpdate).
func (c *Ctx) VerifyUpdate(sh SessionHandle, part []byte) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	if len(part) == 0 {
		// Same NULL-pointer guard as SignUpdate: some implementations reject
		// NULL pPart even when ulPartLen is 0.
		dummy := C.malloc(1)
		defer C.free(dummy)
		return toError(uint(C.ck_verify_update(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(dummy), 0)))
	}
	p, n := cBytes(part)
	defer zfree(p, n)
	return toError(uint(C.ck_verify_update(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n)))
}

// VerifyFinal finishes a multi-part verification against the given signature
// (C_VerifyFinal).
func (c *Ctx) VerifyFinal(sh SessionHandle, signature []byte) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	sig, sn := cBytes(signature)
	defer free(sig)
	return toError(uint(C.ck_verify_final(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(sig), sn)))
}
