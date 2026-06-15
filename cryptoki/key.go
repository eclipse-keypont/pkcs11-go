// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include "shim.h"
*/
import "C"

// GenerateKey generates a secret key from a mechanism and template
// (C_GenerateKey), e.g. an AES key with CKM_AES_KEY_GEN.
func (c *Ctx) GenerateKey(sh SessionHandle, m *Mechanism, tmpl []*Attribute) (ObjectHandle, error) {
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
	rv := C.ck_generate_key(mod, C.CK_SESSION_HANDLE(sh), mech, arr, n, &key)
	if err := toError(uint(rv)); err != nil {
		return 0, err
	}
	return ObjectHandle(key), nil
}

// GenerateKeyPair generates a public/private key pair (C_GenerateKeyPair), e.g.
// an RSA pair with CKM_RSA_PKCS_KEY_PAIR_GEN. It returns the public then the
// private object handle.
func (c *Ctx) GenerateKeyPair(sh SessionHandle, m *Mechanism, public, private []*Attribute) (ObjectHandle, ObjectHandle, error) {
	mod, release, err := c.grab()
	if err != nil {
		return 0, 0, err
	}
	defer release()
	mech, freeMech := cMechanism(m)
	defer freeMech()
	pub, pubN, freePub := cAttributes(public)
	defer freePub()
	priv, privN, freePriv := cAttributes(private)
	defer freePriv()

	var hPub, hPriv C.CK_OBJECT_HANDLE
	rv := C.ck_generate_key_pair(mod, C.CK_SESSION_HANDLE(sh), mech,
		pub, pubN, priv, privN, &hPub, &hPriv)
	if err := toError(uint(rv)); err != nil {
		return 0, 0, err
	}
	return ObjectHandle(hPub), ObjectHandle(hPriv), nil
}
