// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package p11

import (
	"bytes"
	"testing"

	"github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

func TestModuleInfoAndSlots(t *testing.T) {
	if !testReady {
		t.Skip("set PKCS11_MODULE to run p11 integration tests")
	}
	info, err := testMod.Info()
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.CryptokiVersion.Major < 2 {
		t.Fatalf("CryptokiVersion = %s", info.CryptokiVersion)
	}

	ti, err := testSlot.TokenInfo()
	if err != nil {
		t.Fatalf("TokenInfo: %v", err)
	}
	if ti.Label != testLabel {
		t.Fatalf("token label = %q, want %q", ti.Label, testLabel)
	}

	mechs, err := testSlot.Mechanisms()
	if err != nil {
		t.Fatalf("Mechanisms: %v", err)
	}
	if len(mechs) == 0 {
		t.Fatal("no mechanisms reported")
	}
}

func TestSessionGenerateRandom(t *testing.T) {
	sess := requireSession(t)
	b, err := sess.GenerateRandom(24)
	if err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}
	if len(b) != 24 || bytes.Equal(b, make([]byte, 24)) {
		t.Fatalf("bad random output: %x", b)
	}
}

func TestSecretKeyEncryptDecrypt(t *testing.T) {
	sess := requireSession(t)
	key, err := sess.GenerateKey(cryptoki.NewMechanism(cryptoki.CKM_AES_KEY_GEN, nil), aesKeyTemplate("p11-aes"))
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	iv, err := sess.GenerateRandom(16)
	if err != nil {
		t.Fatalf("GenerateRandom(iv): %v", err)
	}
	mech := cryptoki.NewMechanism(cryptoki.CKM_AES_CBC_PAD, iv)
	plain := []byte("high-level round trip")

	ct, err := key.Encrypt(mech, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := key.Decrypt(mech, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plain) {
		t.Fatalf("round trip = %q, want %q", pt, plain)
	}
}

func TestKeyPairSignVerify(t *testing.T) {
	sess := requireSession(t)
	kp, err := sess.GenerateKeyPair(
		cryptoki.NewMechanism(cryptoki.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
		[]*cryptoki.Attribute{
			cryptoki.NewAttribute(cryptoki.CKA_TOKEN, false),
			cryptoki.NewAttribute(cryptoki.CKA_VERIFY, true),
			cryptoki.NewAttribute(cryptoki.CKA_MODULUS_BITS, 2048),
			cryptoki.NewAttribute(cryptoki.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
		},
		[]*cryptoki.Attribute{
			cryptoki.NewAttribute(cryptoki.CKA_TOKEN, false),
			cryptoki.NewAttribute(cryptoki.CKA_PRIVATE, true),
			cryptoki.NewAttribute(cryptoki.CKA_SIGN, true),
		},
	)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	mech := cryptoki.NewMechanism(cryptoki.CKM_SHA256_RSA_PKCS, nil)
	msg := []byte("sign via p11")
	sig, err := kp.Private.Sign(mech, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := kp.Public.Verify(mech, msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	bad := bytes.Clone(sig)
	bad[0] ^= 0xff
	if err := kp.Public.Verify(mech, msg, bad); err == nil {
		t.Fatal("Verify accepted a tampered signature")
	}
}

func TestFindAndDestroy(t *testing.T) {
	sess := requireSession(t)
	const label = "p11-findable"
	if _, err := sess.GenerateKey(cryptoki.NewMechanism(cryptoki.CKM_AES_KEY_GEN, nil), aesKeyTemplate(label)); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	key, err := sess.FindSecretKey(label)
	if err != nil {
		t.Fatalf("FindSecretKey: %v", err)
	}
	got, err := key.Object().Label()
	if err != nil {
		t.Fatalf("Label: %v", err)
	}
	if got != label {
		t.Fatalf("Label = %q, want %q", got, label)
	}

	if err := key.Object().Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if _, err := sess.FindSecretKey(label); err == nil {
		t.Fatal("key still found after Destroy")
	}
}

func TestCopyObject(t *testing.T) {
	sess := requireSession(t)

	key, err := sess.GenerateKey(cryptoki.NewMechanism(cryptoki.CKM_AES_KEY_GEN, nil),
		append(aesKeyTemplate("p11-copy-src"),
			cryptoki.NewAttribute(cryptoki.CKA_COPYABLE, true)))
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cpy, err := key.Object().Copy([]*cryptoki.Attribute{
		cryptoki.NewAttribute(cryptoki.CKA_LABEL, "p11-copy-dst"),
	})
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}

	got, err := cpy.Label()
	if err != nil {
		t.Fatalf("Label on copy: %v", err)
	}
	if got != "p11-copy-dst" {
		t.Fatalf("copy label = %q, want %q", got, "p11-copy-dst")
	}

	key.Object().Destroy()
	cpy.Destroy()
}

func TestMLKEMEncapsulateDecapsulate(t *testing.T) {
	sess := requireSession(t)
	if !testMod.SupportsV32() || !hasMech(t, cryptoki.CKM_ML_KEM) {
		t.Skip("token does not support ML-KEM")
	}

	kp, err := sess.GenerateKeyPair(
		cryptoki.NewMechanism(cryptoki.CKM_ML_KEM_KEY_PAIR_GEN, nil),
		[]*cryptoki.Attribute{
			cryptoki.NewAttribute(cryptoki.CKA_TOKEN, false),
			cryptoki.NewAttribute(cryptoki.CKA_PARAMETER_SET, uint(cryptoki.CKP_ML_KEM_768)),
			cryptoki.NewAttribute(cryptoki.CKA_ENCAPSULATE, true),
		},
		[]*cryptoki.Attribute{
			cryptoki.NewAttribute(cryptoki.CKA_TOKEN, false),
			cryptoki.NewAttribute(cryptoki.CKA_PRIVATE, true),
			cryptoki.NewAttribute(cryptoki.CKA_DECAPSULATE, true),
		},
	)
	if err != nil {
		t.Fatalf("GenerateKeyPair(ML-KEM): %v", err)
	}

	derived := aesKeyTemplate("p11-mlkem-secret")
	ct, encKey, err := kp.Public.Encapsulate(cryptoki.NewMechanism(cryptoki.CKM_ML_KEM, nil), derived)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	decKey, err := kp.Private.Decapsulate(cryptoki.NewMechanism(cryptoki.CKM_ML_KEM, nil), ct, derived)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	// Same shared secret ⇒ AES encrypt/decrypt across the two derived keys works.
	iv, _ := sess.GenerateRandom(16)
	mech := cryptoki.NewMechanism(cryptoki.CKM_AES_CBC_PAD, iv)
	probe := []byte("kem shared secret probe")
	wrapped, err := encKey.Encrypt(mech, probe)
	if err != nil {
		t.Fatalf("Encrypt with encapsulated key: %v", err)
	}
	got, err := decKey.Decrypt(mech, wrapped)
	if err != nil {
		t.Fatalf("Decrypt with decapsulated key: %v", err)
	}
	if !bytes.Equal(got, probe) {
		t.Fatal("ML-KEM shared secret mismatch via p11 layer")
	}
}
