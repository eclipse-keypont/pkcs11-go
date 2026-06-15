// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include "shim.h"
*/
import "C"

// EncryptInit initialises an encryption operation with a key (C_EncryptInit).
func (c *Ctx) EncryptInit(sh SessionHandle, m *Mechanism, key ObjectHandle) error {
	mod, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	mech, freeMech := cMechanism(m)
	defer freeMech()
	return toError(uint(C.ck_encrypt_init(mod, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(key))))
}

// Encrypt encrypts data in a single part and returns the ciphertext (C_Encrypt).
func (c *Ctx) Encrypt(sh SessionHandle, data []byte) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	p, n := cBytes(data)
	defer zfree(p, n)
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_encrypt(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n, out, outLen)
	})
}

// EncryptUpdate encrypts another part of a multi-part operation and returns the
// ciphertext produced so far (C_EncryptUpdate).
func (c *Ctx) EncryptUpdate(sh SessionHandle, part []byte) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	p, n := cBytes(part)
	defer zfree(p, n)
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_encrypt_update(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n, out, outLen)
	})
}

// EncryptFinal finishes a multi-part encryption and returns any remaining
// ciphertext (C_EncryptFinal).
func (c *Ctx) EncryptFinal(sh SessionHandle) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_encrypt_final(m, C.CK_SESSION_HANDLE(sh), out, outLen)
	})
}

// DecryptInit initialises a decryption operation with a key (C_DecryptInit).
func (c *Ctx) DecryptInit(sh SessionHandle, m *Mechanism, key ObjectHandle) error {
	mod, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	mech, freeMech := cMechanism(m)
	defer freeMech()
	return toError(uint(C.ck_decrypt_init(mod, C.CK_SESSION_HANDLE(sh), mech, C.CK_OBJECT_HANDLE(key))))
}

// Decrypt decrypts ciphertext in a single part and returns the plaintext
// (C_Decrypt).
func (c *Ctx) Decrypt(sh SessionHandle, cipher []byte) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	p, n := cBytes(cipher)
	defer free(p)
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_decrypt(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n, out, outLen)
	})
}

// DecryptUpdate decrypts another part of a multi-part operation and returns the
// plaintext produced so far (C_DecryptUpdate).
func (c *Ctx) DecryptUpdate(sh SessionHandle, part []byte) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	p, n := cBytes(part)
	defer free(p)
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_decrypt_update(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n, out, outLen)
	})
}

// DecryptFinal finishes a multi-part decryption and returns any remaining
// plaintext (C_DecryptFinal).
func (c *Ctx) DecryptFinal(sh SessionHandle) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_decrypt_final(m, C.CK_SESSION_HANDLE(sh), out, outLen)
	})
}
