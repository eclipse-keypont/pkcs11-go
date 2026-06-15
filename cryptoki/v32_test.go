// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"bytes"
	"errors"
	"testing"
)

// requireMech returns a logged-in session, skipping the test unless the token
// supports every named mechanism.
func requireMech(t *testing.T, mechs ...uint) SessionHandle {
	t.Helper()
	sh := requireSession(t)
	have := map[uint]bool{}
	list, err := testCtx.GetMechanismList(testSlot)
	if err != nil {
		t.Fatalf("GetMechanismList: %v", err)
	}
	for _, m := range list {
		have[m] = true
	}
	for _, m := range mechs {
		if !have[m] {
			t.Skipf("token does not support mechanism %#x", m)
		}
	}
	return sh
}

// aesRoundTrip encrypts then decrypts a probe under two AES keys and reports
// whether they hold identical key material (used to compare KEM shared secrets
// without reading non-extractable key bytes).
func aesRoundTrip(t *testing.T, sh SessionHandle, encKey, decKey ObjectHandle) bool {
	t.Helper()
	iv, err := testCtx.GenerateRandom(sh, 16)
	if err != nil {
		t.Fatalf("GenerateRandom(iv): %v", err)
	}
	probe := []byte("shared-secret probe message 12345")
	if err := testCtx.EncryptInit(sh, NewMechanism(CKM_AES_CBC_PAD, iv), encKey); err != nil {
		t.Fatalf("EncryptInit: %v", err)
	}
	ct, err := testCtx.Encrypt(sh, probe)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := testCtx.DecryptInit(sh, NewMechanism(CKM_AES_CBC_PAD, iv), decKey); err != nil {
		t.Fatalf("DecryptInit: %v", err)
	}
	pt, err := testCtx.Decrypt(sh, ct)
	if err != nil {
		return false // wrong key → padding/decrypt failure
	}
	return bytes.Equal(pt, probe)
}

func TestIntegrationMLKEM(t *testing.T) {
	sh := requireMech(t, CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM)

	pub, priv, err := testCtx.GenerateKeyPair(sh,
		NewMechanism(CKM_ML_KEM_KEY_PAIR_GEN, nil),
		[]*Attribute{
			NewAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_PARAMETER_SET, uint(CKP_ML_KEM_768)),
			NewAttribute(CKA_ENCAPSULATE, true),
		},
		[]*Attribute{
			NewAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_PRIVATE, true),
			NewAttribute(CKA_DECAPSULATE, true),
		},
	)
	if err != nil {
		t.Fatalf("GenerateKeyPair(ML-KEM): %v", err)
	}

	derived := []*Attribute{
		NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
		NewAttribute(CKA_KEY_TYPE, uint(CKK_AES)),
		NewAttribute(CKA_VALUE_LEN, 32),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DECRYPT, true),
	}

	ct, encKey, err := testCtx.EncapsulateKey(sh, NewMechanism(CKM_ML_KEM, nil), pub, derived)
	if err != nil {
		t.Fatalf("EncapsulateKey: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("EncapsulateKey returned empty ciphertext")
	}

	decKey, err := testCtx.DecapsulateKey(sh, NewMechanism(CKM_ML_KEM, nil), priv, derived, ct)
	if err != nil {
		t.Fatalf("DecapsulateKey: %v", err)
	}

	if !aesRoundTrip(t, sh, encKey, decKey) {
		t.Fatal("encapsulated and decapsulated keys differ — shared secret mismatch")
	}
}

func TestIntegrationMLDSA(t *testing.T) {
	sh := requireMech(t, CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA)
	signVerify(t, sh, CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA,
		NewAttribute(CKA_PARAMETER_SET, uint(CKP_ML_DSA_65)))
}

func TestIntegrationSLHDSA(t *testing.T) {
	sh := requireMech(t, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA)
	// The "s" (small-signature) parameter sets keep this fast enough for CI.
	signVerify(t, sh, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA,
		NewAttribute(CKA_PARAMETER_SET, uint(CKP_SLH_DSA_SHA2_128S)))
}

// signVerify generates a PQC signing key pair with the given parameter-set
// attribute, then checks a good signature verifies and a tampered one does not.
func signVerify(t *testing.T, sh SessionHandle, keygen, sign uint, paramSet *Attribute) {
	t.Helper()
	pub, priv, err := testCtx.GenerateKeyPair(sh,
		NewMechanism(keygen, nil),
		[]*Attribute{NewAttribute(CKA_TOKEN, false), paramSet, NewAttribute(CKA_VERIFY, true)},
		[]*Attribute{NewAttribute(CKA_TOKEN, false), NewAttribute(CKA_PRIVATE, true), NewAttribute(CKA_SIGN, true)},
	)
	if err != nil {
		t.Fatalf("GenerateKeyPair(%#x): %v", keygen, err)
	}

	data := []byte("post-quantum message")
	if err := testCtx.SignInit(sh, NewMechanism(sign, nil), priv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	sig, err := testCtx.Sign(sh, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := testCtx.VerifyInit(sh, NewMechanism(sign, nil), pub); err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	if err := testCtx.Verify(sh, data, sig); err != nil {
		t.Fatalf("Verify (valid): %v", err)
	}

	bad := bytes.Clone(sig)
	bad[0] ^= 0xff
	if err := testCtx.VerifyInit(sh, NewMechanism(sign, nil), pub); err != nil {
		t.Fatalf("VerifyInit (tamper): %v", err)
	}
	if err := testCtx.Verify(sh, data, bad); err == nil {
		t.Fatal("Verify accepted a tampered signature")
	}
}

func TestIntegrationStatelessVerify(t *testing.T) {
	// The v3.2 stateless verify (C_VerifySignature) takes the signature up front
	// at Init, then only the data. Exercised here with ML-DSA.
	sh := requireMech(t, CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA)

	pub, priv, err := testCtx.GenerateKeyPair(sh,
		NewMechanism(CKM_ML_DSA_KEY_PAIR_GEN, nil),
		[]*Attribute{NewAttribute(CKA_TOKEN, false), NewAttribute(CKA_PARAMETER_SET, uint(CKP_ML_DSA_65)), NewAttribute(CKA_VERIFY, true)},
		[]*Attribute{NewAttribute(CKA_TOKEN, false), NewAttribute(CKA_PRIVATE, true), NewAttribute(CKA_SIGN, true)},
	)
	if err != nil {
		t.Fatalf("GenerateKeyPair(ML-DSA): %v", err)
	}

	data := []byte("verify me statelessly, in one and many parts")
	if err := testCtx.SignInit(sh, NewMechanism(CKM_ML_DSA, nil), priv); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	sig, err := testCtx.Sign(sh, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Single-part stateless verify.
	if err := testCtx.VerifySignatureInit(sh, NewMechanism(CKM_ML_DSA, nil), pub, sig); err != nil {
		if errors.Is(err, Error(CKR_FUNCTION_NOT_SUPPORTED)) {
			t.Skip("token does not implement C_VerifySignature")
		}
		t.Fatalf("VerifySignatureInit: %v", err)
	}
	if err := testCtx.VerifySignature(sh, data); err != nil {
		t.Fatalf("VerifySignature (valid): %v", err)
	}

	// Multi-part stateless verify over the same signature.
	if err := testCtx.VerifySignatureInit(sh, NewMechanism(CKM_ML_DSA, nil), pub, sig); err != nil {
		t.Fatalf("VerifySignatureInit (multipart): %v", err)
	}
	if err := testCtx.VerifySignatureUpdate(sh, data[:10]); err != nil {
		t.Fatalf("VerifySignatureUpdate: %v", err)
	}
	if err := testCtx.VerifySignatureUpdate(sh, data[10:]); err != nil {
		t.Fatalf("VerifySignatureUpdate: %v", err)
	}
	if err := testCtx.VerifySignatureFinal(sh); err != nil {
		t.Fatalf("VerifySignatureFinal (valid): %v", err)
	}
}

func TestIntegrationGetSessionValidationFlags(t *testing.T) {
	if !testReady {
		t.Skip("set PKCS11_MODULE to run integration tests")
	}
	if !testCtx.SupportsV32() {
		t.Skip("module does not expose the PKCS #11 v3.2 interface")
	}
	sh := requireSession(t)
	// flagType 0 selects the session's current validation state. A token that
	// does not implement this call returns CKR_FUNCTION_NOT_SUPPORTED.
	_, err := testCtx.GetSessionValidationFlags(sh, 0)
	if err != nil && !errors.Is(err, Error(CKR_FUNCTION_NOT_SUPPORTED)) {
		t.Fatalf("GetSessionValidationFlags: %v", err)
	}
}

func TestIntegrationAESKeyWrap(t *testing.T) {
	sh := requireMech(t, CKM_AES_KEY_GEN, CKM_AES_KEY_WRAP)

	// A wrapping KEK and a target key, both AES-256.
	kek, err := testCtx.GenerateKey(sh, NewMechanism(CKM_AES_KEY_GEN, nil), []*Attribute{
		NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
		NewAttribute(CKA_KEY_TYPE, uint(CKK_AES)),
		NewAttribute(CKA_VALUE_LEN, 32),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_WRAP, true),
		NewAttribute(CKA_UNWRAP, true),
	})
	if err != nil {
		t.Fatalf("GenerateKey(KEK): %v", err)
	}
	target, err := testCtx.GenerateKey(sh, NewMechanism(CKM_AES_KEY_GEN, nil), []*Attribute{
		NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
		NewAttribute(CKA_KEY_TYPE, uint(CKK_AES)),
		NewAttribute(CKA_VALUE_LEN, 32),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_EXTRACTABLE, true),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DECRYPT, true),
	})
	if err != nil {
		t.Fatalf("GenerateKey(target): %v", err)
	}

	wrapped, err := testCtx.WrapKey(sh, NewMechanism(CKM_AES_KEY_WRAP, nil), kek, target)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if len(wrapped) == 0 {
		t.Fatal("WrapKey returned no bytes")
	}

	unwrapped, err := testCtx.UnwrapKey(sh, NewMechanism(CKM_AES_KEY_WRAP, nil), kek, wrapped, []*Attribute{
		NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
		NewAttribute(CKA_KEY_TYPE, uint(CKK_AES)),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DECRYPT, true),
	})
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}

	// The unwrapped key must be the original: original encrypts, unwrapped decrypts.
	if !aesRoundTrip(t, sh, target, unwrapped) {
		t.Fatal("unwrapped key does not match the wrapped original")
	}
}
