// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"bytes"
	"errors"
	"testing"
)

// genAESKey generates a session AES key with the given extra attributes.
func genAESKey(t *testing.T, sh SessionHandle, bits int, extra ...*Attribute) ObjectHandle {
	t.Helper()
	tmpl := append([]*Attribute{
		NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
		NewAttribute(CKA_KEY_TYPE, uint(CKK_AES)),
		NewAttribute(CKA_VALUE_LEN, bits/8),
		NewAttribute(CKA_TOKEN, false),
	}, extra...)
	key, err := testCtx.GenerateKey(sh, NewMechanism(CKM_AES_KEY_GEN, nil), tmpl)
	if err != nil {
		t.Fatalf("GenerateKey(AES-%d): %v", bits, err)
	}
	return key
}

func TestIntegrationAESGCM(t *testing.T) {
	sh := requireMech(t, CKM_AES_KEY_GEN, CKM_AES_GCM)
	key := genAESKey(t, sh, 256, NewAttribute(CKA_ENCRYPT, true), NewAttribute(CKA_DECRYPT, true))

	iv, err := testCtx.GenerateRandom(sh, 12) // 96-bit GCM nonce
	if err != nil {
		t.Fatalf("GenerateRandom(iv): %v", err)
	}
	aad := []byte("associated header")
	plain := []byte("authenticated and encrypted")
	mech := NewMechanismWithParams(CKM_AES_GCM, NewGCMParams(iv, aad, 128))

	if err := testCtx.EncryptInit(sh, mech, key); err != nil {
		t.Fatalf("EncryptInit(GCM): %v", err)
	}
	ct, err := testCtx.Encrypt(sh, plain)
	if err != nil {
		t.Fatalf("Encrypt(GCM): %v", err)
	}
	if len(ct) <= len(plain) {
		t.Fatalf("GCM ciphertext (%d) should exceed plaintext (%d) by the tag", len(ct), len(plain))
	}

	if err := testCtx.DecryptInit(sh, mech, key); err != nil {
		t.Fatalf("DecryptInit(GCM): %v", err)
	}
	pt, err := testCtx.Decrypt(sh, ct)
	if err != nil {
		t.Fatalf("Decrypt(GCM): %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatalf("GCM round-trip = %q, want %q", pt, plain)
	}
}

func TestIntegrationRSAOAEP(t *testing.T) {
	sh := requireMech(t, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS_OAEP)

	pub, priv, err := testCtx.GenerateKeyPair(sh,
		NewMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
		[]*Attribute{
			NewAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_ENCRYPT, true),
			NewAttribute(CKA_MODULUS_BITS, 2048),
			NewAttribute(CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		},
		[]*Attribute{
			NewAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_PRIVATE, true),
			NewAttribute(CKA_DECRYPT, true),
		},
	)
	if err != nil {
		t.Fatalf("GenerateKeyPair(RSA): %v", err)
	}

	mech := NewMechanismWithParams(CKM_RSA_PKCS_OAEP,
		NewOAEPParams(CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nil))
	secret := []byte("a short secret")

	if err := testCtx.EncryptInit(sh, mech, pub); err != nil {
		t.Fatalf("EncryptInit(OAEP): %v", err)
	}
	ct, err := testCtx.Encrypt(sh, secret)
	if err != nil {
		t.Fatalf("Encrypt(OAEP): %v", err)
	}
	if err := testCtx.DecryptInit(sh, mech, priv); err != nil {
		t.Fatalf("DecryptInit(OAEP): %v", err)
	}
	pt, err := testCtx.Decrypt(sh, ct)
	if err != nil {
		t.Fatalf("Decrypt(OAEP): %v", err)
	}
	if !bytes.Equal(pt, secret) {
		t.Fatalf("OAEP round-trip = %q, want %q", pt, secret)
	}
}

func TestIntegrationECDH1Derive(t *testing.T) {
	sh := requireMech(t, CKM_EC_KEY_PAIR_GEN, CKM_ECDH1_DERIVE)

	// DER-encoded OID for the NIST P-256 curve (prime256v1).
	p256 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

	genEC := func(name string) (pub, priv ObjectHandle) {
		var err error
		pub, priv, err = testCtx.GenerateKeyPair(sh,
			NewMechanism(CKM_EC_KEY_PAIR_GEN, nil),
			[]*Attribute{
				NewAttribute(CKA_TOKEN, false),
				NewAttribute(CKA_EC_PARAMS, p256),
				NewAttribute(CKA_DERIVE, true),
			},
			[]*Attribute{
				NewAttribute(CKA_TOKEN, false),
				NewAttribute(CKA_PRIVATE, true),
				NewAttribute(CKA_DERIVE, true),
			},
		)
		if err != nil {
			t.Fatalf("GenerateKeyPair(EC %s): %v", name, err)
		}
		return pub, priv
	}

	ecPoint := func(pub ObjectHandle) []byte {
		attrs, err := testCtx.GetAttributeValue(sh, pub, []*Attribute{NewAttribute(CKA_EC_POINT, nil)})
		if err != nil {
			t.Fatalf("GetAttributeValue(CKA_EC_POINT): %v", err)
		}
		return attrs[0].Value
	}

	pubA, privA := genEC("A")
	pubB, privB := genEC("B")

	derive := func(priv ObjectHandle, peerPoint []byte) ObjectHandle {
		mech := NewMechanismWithParams(CKM_ECDH1_DERIVE, NewECDH1DeriveParams(CKD_NULL, nil, peerPoint))
		key, err := testCtx.DeriveKey(sh, mech, priv, []*Attribute{
			NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
			NewAttribute(CKA_KEY_TYPE, uint(CKK_AES)),
			NewAttribute(CKA_VALUE_LEN, 32),
			NewAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_ENCRYPT, true),
			NewAttribute(CKA_DECRYPT, true),
		})
		if err != nil {
			t.Fatalf("DeriveKey(ECDH1): %v", err)
		}
		return key
	}

	keyA := derive(privA, ecPoint(pubB))
	keyB := derive(privB, ecPoint(pubA))

	if !aesRoundTrip(t, sh, keyA, keyB) {
		t.Fatal("ECDH1 derived secrets differ between the two parties")
	}
}

func TestIntegrationAuthenticatedWrap(t *testing.T) {
	sh := requireMech(t, CKM_AES_KEY_GEN, CKM_AES_GCM)

	kek := genAESKey(t, sh, 256, NewAttribute(CKA_WRAP, true), NewAttribute(CKA_UNWRAP, true))
	target := genAESKey(t, sh, 256,
		NewAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DECRYPT, true))

	iv, err := testCtx.GenerateRandom(sh, 12)
	if err != nil {
		t.Fatalf("GenerateRandom(iv): %v", err)
	}
	aad := []byte("wrap-context-v1")
	// AAD is passed to the authenticated-wrap call directly, so the GCM params
	// carry only the nonce and tag length.
	mech := NewMechanismWithParams(CKM_AES_GCM, NewGCMParams(iv, nil, 128))

	wrapped, err := testCtx.WrapKeyAuthenticated(sh, mech, kek, target, aad)
	if err != nil {
		if errors.Is(err, Error(CKR_FUNCTION_NOT_SUPPORTED)) || errors.Is(err, Error(CKR_MECHANISM_INVALID)) {
			t.Skipf("token does not support authenticated wrap with AES-GCM: %v", err)
		}
		t.Fatalf("WrapKeyAuthenticated: %v", err)
	}

	unwrapTmpl := []*Attribute{
		NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
		NewAttribute(CKA_KEY_TYPE, uint(CKK_AES)),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DECRYPT, true),
	}
	unwrapped, err := testCtx.UnwrapKeyAuthenticated(sh, mech, kek, wrapped, aad, unwrapTmpl)
	if err != nil {
		t.Fatalf("UnwrapKeyAuthenticated: %v", err)
	}
	if !aesRoundTrip(t, sh, target, unwrapped) {
		t.Fatal("authenticated-unwrapped key does not match the original")
	}

	// Tampered associated data must make the unwrap fail authentication.
	if _, err := testCtx.UnwrapKeyAuthenticated(sh, mech, kek, wrapped, []byte("wrong-context"), unwrapTmpl); err == nil {
		t.Fatal("UnwrapKeyAuthenticated accepted wrong associated data")
	}
}
