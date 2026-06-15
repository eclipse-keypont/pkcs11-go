// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestIntegrationGetInfo(t *testing.T) {
	if !testReady {
		t.Skip("set PKCS11_MODULE to run integration tests")
	}
	info, err := testCtx.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.CryptokiVersion.Major < 2 {
		t.Fatalf("CryptokiVersion = %s, want >= 2.x", info.CryptokiVersion)
	}
	if info.ManufacturerID == "" {
		t.Error("empty ManufacturerID")
	}
	t.Logf("module: cryptoki %s, %q, v3.2=%v", info.CryptokiVersion, info.ManufacturerID, testCtx.SupportsV32())
}

func TestIntegrationTokenInfo(t *testing.T) {
	if !testReady {
		t.Skip("set PKCS11_MODULE to run integration tests")
	}
	ti, err := testCtx.GetTokenInfo(testSlot)
	if err != nil {
		t.Fatalf("GetTokenInfo: %v", err)
	}
	if ti.Label != testLabel {
		t.Fatalf("Label = %q, want %q", ti.Label, testLabel)
	}
	if ti.Flags&CKF_TOKEN_INITIALIZED == 0 {
		t.Errorf("CKF_TOKEN_INITIALIZED not set (flags=%#x)", ti.Flags)
	}
	if ti.Flags&CKF_USER_PIN_INITIALIZED == 0 {
		t.Errorf("CKF_USER_PIN_INITIALIZED not set (flags=%#x)", ti.Flags)
	}
}

func TestIntegrationMechanismList(t *testing.T) {
	if !testReady {
		t.Skip("set PKCS11_MODULE to run integration tests")
	}
	mechs, err := testCtx.GetMechanismList(testSlot)
	if err != nil {
		t.Fatalf("GetMechanismList: %v", err)
	}
	if len(mechs) == 0 {
		t.Fatal("token reports no mechanisms")
	}
	if _, err := testCtx.GetMechanismInfo(testSlot, mechs[0]); err != nil {
		t.Fatalf("GetMechanismInfo(%#x): %v", mechs[0], err)
	}
}

func TestIntegrationGenerateRandom(t *testing.T) {
	sh := requireSession(t)
	a, err := testCtx.GenerateRandom(sh, 32)
	if err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}
	if len(a) != 32 {
		t.Fatalf("got %d bytes, want 32", len(a))
	}
	if bytes.Equal(a, make([]byte, 32)) {
		t.Fatal("random output is all zero")
	}
	b, _ := testCtx.GenerateRandom(sh, 32)
	if bytes.Equal(a, b) {
		t.Fatal("two random draws are identical")
	}
}

func TestIntegrationDigest(t *testing.T) {
	sh := requireSession(t)
	msg := []byte("the quick brown fox")
	want := sha256.Sum256(msg)

	if err := testCtx.DigestInit(sh, NewMechanism(CKM_SHA256, nil)); err != nil {
		t.Fatalf("DigestInit: %v", err)
	}
	got, err := testCtx.Digest(sh, msg)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("one-shot digest = %x, want %x", got, want)
	}

	// Multi-part must match the one-shot result.
	if err := testCtx.DigestInit(sh, NewMechanism(CKM_SHA256, nil)); err != nil {
		t.Fatalf("DigestInit (multipart): %v", err)
	}
	if err := testCtx.DigestUpdate(sh, msg[:4]); err != nil {
		t.Fatalf("DigestUpdate: %v", err)
	}
	if err := testCtx.DigestUpdate(sh, msg[4:]); err != nil {
		t.Fatalf("DigestUpdate: %v", err)
	}
	multi, err := testCtx.DigestFinal(sh)
	if err != nil {
		t.Fatalf("DigestFinal: %v", err)
	}
	if !bytes.Equal(multi, want[:]) {
		t.Fatalf("multi-part digest = %x, want %x", multi, want)
	}
}

func TestIntegrationAESEncryptDecrypt(t *testing.T) {
	sh := requireSession(t)

	key, err := testCtx.GenerateKey(sh, NewMechanism(CKM_AES_KEY_GEN, nil), []*Attribute{
		NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
		NewAttribute(CKA_KEY_TYPE, uint(CKK_AES)),
		NewAttribute(CKA_VALUE_LEN, 32),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DECRYPT, true),
	})
	if err != nil {
		t.Fatalf("GenerateKey(AES): %v", err)
	}

	iv, err := testCtx.GenerateRandom(sh, 16)
	if err != nil {
		t.Fatalf("GenerateRandom(iv): %v", err)
	}
	plain := []byte("attack at dawn — padded by CBC_PAD")

	if err := testCtx.EncryptInit(sh, NewMechanism(CKM_AES_CBC_PAD, iv), key); err != nil {
		t.Fatalf("EncryptInit: %v", err)
	}
	ct, err := testCtx.Encrypt(sh, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ct, plain) {
		t.Fatal("ciphertext equals plaintext")
	}

	if err := testCtx.DecryptInit(sh, NewMechanism(CKM_AES_CBC_PAD, iv), key); err != nil {
		t.Fatalf("DecryptInit: %v", err)
	}
	pt, err := testCtx.Decrypt(sh, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatalf("round-trip = %q, want %q", pt, plain)
	}
}

func TestIntegrationRSASignVerify(t *testing.T) {
	sh := requireSession(t)

	pub, priv, err := testCtx.GenerateKeyPair(sh,
		NewMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
		[]*Attribute{
			NewAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_VERIFY, true),
			NewAttribute(CKA_MODULUS_BITS, 2048),
			NewAttribute(CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		},
		[]*Attribute{
			NewAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_PRIVATE, true),
			NewAttribute(CKA_SIGN, true),
		},
	)
	if err != nil {
		t.Fatalf("GenerateKeyPair(RSA): %v", err)
	}

	data := []byte("sign this message")
	if err := testCtx.SignInit(sh, NewMechanism(CKM_SHA256_RSA_PKCS, nil), priv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	sig, err := testCtx.Sign(sh, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := testCtx.VerifyInit(sh, NewMechanism(CKM_SHA256_RSA_PKCS, nil), pub); err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	if err := testCtx.Verify(sh, data, sig); err != nil {
		t.Fatalf("Verify (valid signature): %v", err)
	}

	// A tampered signature must fail verification.
	bad := bytes.Clone(sig)
	bad[0] ^= 0xff
	if err := testCtx.VerifyInit(sh, NewMechanism(CKM_SHA256_RSA_PKCS, nil), pub); err != nil {
		t.Fatalf("VerifyInit (tamper): %v", err)
	}
	if err := testCtx.Verify(sh, data, bad); err == nil {
		t.Fatal("Verify accepted a tampered signature")
	}
}

func TestIntegrationFindAndDestroy(t *testing.T) {
	sh := requireSession(t)
	const label = "ckgo-find-me"

	key, err := testCtx.GenerateKey(sh, NewMechanism(CKM_AES_KEY_GEN, nil), []*Attribute{
		NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
		NewAttribute(CKA_KEY_TYPE, uint(CKK_AES)),
		NewAttribute(CKA_VALUE_LEN, 16),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_LABEL, label),
	})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if err := testCtx.FindObjectsInit(sh, []*Attribute{NewAttribute(CKA_LABEL, label)}); err != nil {
		t.Fatalf("FindObjectsInit: %v", err)
	}
	found, err := testCtx.FindObjects(sh, 16)
	if err != nil {
		t.Fatalf("FindObjects: %v", err)
	}
	if err := testCtx.FindObjectsFinal(sh); err != nil {
		t.Fatalf("FindObjectsFinal: %v", err)
	}
	if len(found) != 1 || found[0] != key {
		t.Fatalf("find by label returned %v, want exactly the generated key %d", found, key)
	}

	attrs, err := testCtx.GetAttributeValue(sh, key, []*Attribute{NewAttribute(CKA_CLASS, nil)})
	if err != nil {
		t.Fatalf("GetAttributeValue: %v", err)
	}
	if len(attrs) != 1 || leUint(attrs[0].Value) != uint64(CKO_SECRET_KEY) {
		t.Fatalf("CKA_CLASS = %v, want CKO_SECRET_KEY", attrs)
	}

	if err := testCtx.DestroyObject(sh, key); err != nil {
		t.Fatalf("DestroyObject: %v", err)
	}
}
