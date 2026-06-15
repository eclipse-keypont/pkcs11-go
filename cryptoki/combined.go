// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include "shim.h"
*/
import "C"

// DigestEncryptUpdate simultaneously digests and encrypts one part of a
// multi-part operation (C_DigestEncryptUpdate). The session must have been
// prepared with both DigestInit and EncryptInit beforehand.
func (c *Ctx) DigestEncryptUpdate(sh SessionHandle, part []byte) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	p, n := cBytes(part)
	defer free(p)
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_digest_encrypt_update(m, C.CK_SESSION_HANDLE(sh),
			(C.CK_BYTE_PTR)(p), n, out, outLen)
	})
}

// DecryptDigestUpdate simultaneously decrypts and digests one part of a
// multi-part operation (C_DecryptDigestUpdate). The session must have been
// prepared with both DecryptInit and DigestInit beforehand.
func (c *Ctx) DecryptDigestUpdate(sh SessionHandle, cipher []byte) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	p, n := cBytes(cipher)
	defer free(p)
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_decrypt_digest_update(m, C.CK_SESSION_HANDLE(sh),
			(C.CK_BYTE_PTR)(p), n, out, outLen)
	})
}

// SignEncryptUpdate simultaneously signs and encrypts one part of a multi-part
// operation (C_SignEncryptUpdate). The session must have been prepared with
// both SignInit and EncryptInit beforehand.
func (c *Ctx) SignEncryptUpdate(sh SessionHandle, part []byte) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	p, n := cBytes(part)
	defer free(p)
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_sign_encrypt_update(m, C.CK_SESSION_HANDLE(sh),
			(C.CK_BYTE_PTR)(p), n, out, outLen)
	})
}

// DecryptVerifyUpdate simultaneously decrypts and feeds plaintext into a
// running verify operation (C_DecryptVerifyUpdate). The session must have been
// prepared with both DecryptInit and VerifyInit beforehand. Call DecryptFinal
// and VerifyFinal when all parts have been processed.
func (c *Ctx) DecryptVerifyUpdate(sh SessionHandle, cipher []byte) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	p, n := cBytes(cipher)
	defer free(p)
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_decrypt_verify_update(m, C.CK_SESSION_HANDLE(sh),
			(C.CK_BYTE_PTR)(p), n, out, outLen)
	})
}
