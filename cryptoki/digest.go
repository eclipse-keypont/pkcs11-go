// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include "shim.h"
*/
import "C"

// DigestInit initialises a digest operation (C_DigestInit).
func (c *Ctx) DigestInit(sh SessionHandle, m *Mechanism) error {
	mod, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	mech, freeMech := cMechanism(m)
	defer freeMech()
	return toError(uint(C.ck_digest_init(mod, C.CK_SESSION_HANDLE(sh), mech)))
}

// Digest digests data in a single part and returns the message digest
// (C_Digest).
func (c *Ctx) Digest(sh SessionHandle, data []byte) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	p, n := cBytes(data)
	defer zfree(p, n)
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_digest(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n, out, outLen)
	})
}

// DigestUpdate feeds another part of the message into a multi-part digest
// (C_DigestUpdate).
func (c *Ctx) DigestUpdate(sh SessionHandle, data []byte) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	p, n := cBytes(data)
	defer zfree(p, n)
	return toError(uint(C.ck_digest_update(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n)))
}

// DigestKey continues a multi-part digest with the value of a secret key
// (C_DigestKey).
func (c *Ctx) DigestKey(sh SessionHandle, key ObjectHandle) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	return toError(uint(C.ck_digest_key(m, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(key))))
}

// DigestFinal finishes a multi-part digest and returns the message digest
// (C_DigestFinal).
func (c *Ctx) DigestFinal(sh SessionHandle) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_digest_final(m, C.CK_SESSION_HANDLE(sh), out, outLen)
	})
}
