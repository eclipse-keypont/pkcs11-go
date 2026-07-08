// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"bytes"
	"errors"
	"testing"
)

// ── CopyObject ────────────────────────────────────────────────────────────────

func TestIntegrationCopyObject(t *testing.T) {
	sh := requireSession(t)

	// Create a session AES-256 key to copy.
	orig, err := genAESKeyRaw(t, sh, "copy-src")
	if err != nil {
		t.Fatalf("create source key: %v", err)
	}

	// Copy it, overriding the label.
	copyTmpl := []*Attribute{NewAttribute(CKA_LABEL, "copy-dst")}
	cpy, err := testCtx.CopyObject(sh, orig, copyTmpl)
	if err != nil {
		t.Fatalf("CopyObject: %v", err)
	}

	// Both handles should have the right labels.
	for _, tc := range []struct {
		name   string
		handle ObjectHandle
		want   string
	}{
		{"original", orig, "copy-src"},
		{"copy", cpy, "copy-dst"},
	} {
		attrs, err := testCtx.GetAttributeValue(sh, tc.handle,
			[]*Attribute{NewAttribute(CKA_LABEL, nil)})
		if err != nil {
			t.Fatalf("%s GetAttributeValue: %v", tc.name, err)
		}
		got := string(attrs[0].Value)
		if got != tc.want {
			t.Errorf("%s label = %q, want %q", tc.name, got, tc.want)
		}
	}

	_ = testCtx.DestroyObject(sh, orig)
	_ = testCtx.DestroyObject(sh, cpy)
}

// ── WaitForSlotEvent ──────────────────────────────────────────────────────────

func TestIntegrationWaitForSlotEvent(t *testing.T) {
	if !testReady {
		t.Skip("set PKCS11_MODULE to run integration tests")
	}
	// CKF_DONT_BLOCK = 1: return immediately. With a software token no physical
	// slot events occur, so CKR_NO_EVENT is the expected result.
	_, err := testCtx.WaitForSlotEvent(CKF_DONT_BLOCK)
	if err == nil {
		return // a pending event is also valid
	}
	if !errors.Is(err, Error(CKR_NO_EVENT)) {
		t.Fatalf("WaitForSlotEvent: got %v, want CKR_NO_EVENT or nil", err)
	}
}

// ── GetOperationState / SetOperationState ─────────────────────────────────────

func TestIntegrationOperationState(t *testing.T) {
	sh := requireSession(t)

	// Init a digest so there is state to save.
	if err := testCtx.DigestInit(sh, NewMechanism(CKM_SHA256, nil)); err != nil {
		t.Fatalf("DigestInit: %v", err)
	}
	data := []byte("operation state probe")
	if err := testCtx.DigestUpdate(sh, data); err != nil {
		t.Fatalf("DigestUpdate: %v", err)
	}

	// Save state.
	state, err := testCtx.GetOperationState(sh)
	if err != nil {
		if errors.Is(err, Error(CKR_STATE_UNSAVEABLE)) ||
			errors.Is(err, Error(CKR_FUNCTION_NOT_SUPPORTED)) {
			t.Skipf("GetOperationState not supported by this module: %v", err)
		}
		t.Fatalf("GetOperationState: %v", err)
	}
	if len(state) == 0 {
		t.Fatal("GetOperationState returned empty state")
	}

	// Finish the original digest.
	digest1, err := testCtx.DigestFinal(sh)
	if err != nil {
		t.Fatalf("DigestFinal (original): %v", err)
	}

	// Restore state into a second session and finish there.
	sh2 := requireSession(t)

	if err := testCtx.SetOperationState(sh2, state, 0, 0); err != nil {
		if errors.Is(err, Error(CKR_SAVED_STATE_INVALID)) ||
			errors.Is(err, Error(CKR_FUNCTION_NOT_SUPPORTED)) {
			t.Skipf("SetOperationState not supported: %v", err)
		}
		t.Fatalf("SetOperationState: %v", err)
	}
	digest2, err := testCtx.DigestFinal(sh2)
	if err != nil {
		t.Fatalf("DigestFinal (restored): %v", err)
	}

	if !bytes.Equal(digest1, digest2) {
		t.Fatalf("digests differ after state restore:\n  original: %x\n  restored: %x",
			digest1, digest2)
	}
}

// ── Combined streaming ops ────────────────────────────────────────────────────

// TestIntegrationDigestEncryptUpdate tests C_DigestEncryptUpdate +
// C_DecryptDigestUpdate. Most software tokens return CKR_FUNCTION_NOT_SUPPORTED;
// the test skips gracefully in that case.
func TestIntegrationDigestEncryptUpdate(t *testing.T) {
	sh := requireSession(t)

	keyH, err := genAESKeyRaw(t, sh, "deu-key")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	defer func() { _ = testCtx.DestroyObject(sh, keyH) }()

	iv, err := testCtx.GenerateRandom(sh, 16)
	if err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}

	if err := testCtx.DigestInit(sh, NewMechanism(CKM_SHA256, nil)); err != nil {
		t.Fatalf("DigestInit: %v", err)
	}
	if err := testCtx.EncryptInit(sh, NewMechanism(CKM_AES_CBC_PAD, iv), keyH); err != nil {
		// CKR_OPERATION_ACTIVE means the module does not allow two concurrent
		// per-session operations — combined ops are unsupported.
		if errors.Is(err, Error(CKR_OPERATION_ACTIVE)) {
			t.Skipf("module does not support concurrent digest+encrypt sessions")
		}
		t.Fatalf("EncryptInit: %v", err)
	}

	plain := []byte("digest+encrypt combined streaming")
	ct, err := testCtx.DigestEncryptUpdate(sh, plain)
	if err != nil {
		if errors.Is(err, Error(CKR_FUNCTION_NOT_SUPPORTED)) {
			t.Skipf("DigestEncryptUpdate not supported by this module")
		}
		t.Fatalf("DigestEncryptUpdate: %v", err)
	}
	tail, err := testCtx.EncryptFinal(sh)
	if err != nil {
		t.Fatalf("EncryptFinal: %v", err)
	}
	ciphertext := append(ct, tail...)
	digest, err := testCtx.DigestFinal(sh)
	if err != nil {
		t.Fatalf("DigestFinal: %v", err)
	}

	// Reverse: DecryptDigestUpdate.
	if err := testCtx.DigestInit(sh, NewMechanism(CKM_SHA256, nil)); err != nil {
		t.Fatalf("DigestInit(2): %v", err)
	}
	if err := testCtx.DecryptInit(sh, NewMechanism(CKM_AES_CBC_PAD, iv), keyH); err != nil {
		t.Fatalf("DecryptInit: %v", err)
	}
	pt, err := testCtx.DecryptDigestUpdate(sh, ciphertext)
	if err != nil {
		if errors.Is(err, Error(CKR_FUNCTION_NOT_SUPPORTED)) {
			t.Skipf("DecryptDigestUpdate not supported by this module")
		}
		t.Fatalf("DecryptDigestUpdate: %v", err)
	}
	ptTail, err := testCtx.DecryptFinal(sh)
	if err != nil {
		t.Fatalf("DecryptFinal: %v", err)
	}
	digest2, err := testCtx.DigestFinal(sh)
	if err != nil {
		t.Fatalf("DigestFinal(2): %v", err)
	}

	plainGot := append(pt, ptTail...)
	if !bytes.Equal(plainGot, plain) {
		t.Fatalf("round-trip mismatch: got %q, want %q", plainGot, plain)
	}
	if !bytes.Equal(digest, digest2) {
		t.Fatalf("digest mismatch: encrypt-side %x, decrypt-side %x", digest, digest2)
	}
}

// TestIntegrationSignEncryptUpdate tests C_SignEncryptUpdate +
// C_DecryptVerifyUpdate. Skips if the module does not support combined ops.
func TestIntegrationSignEncryptUpdate(t *testing.T) {
	sh := requireSession(t)

	pubH, privH, err := genRSAKeyPairRaw(t, sh)
	if err != nil {
		t.Fatalf("generate RSA key pair: %v", err)
	}
	defer func() { _ = testCtx.DestroyObject(sh, pubH) }()
	defer func() { _ = testCtx.DestroyObject(sh, privH) }()

	encH, err := genAESKeyRaw(t, sh, "seu-enc")
	if err != nil {
		t.Fatalf("generate AES key: %v", err)
	}
	defer func() { _ = testCtx.DestroyObject(sh, encH) }()

	iv, err := testCtx.GenerateRandom(sh, 16)
	if err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}

	if err := testCtx.SignInit(sh, NewMechanism(CKM_SHA256_RSA_PKCS, nil), privH); err != nil {
		t.Fatalf("SignInit: %v", err)
	}
	if err := testCtx.EncryptInit(sh, NewMechanism(CKM_AES_CBC_PAD, iv), encH); err != nil {
		if errors.Is(err, Error(CKR_OPERATION_ACTIVE)) {
			t.Skipf("module does not support concurrent sign+encrypt sessions")
		}
		t.Fatalf("EncryptInit: %v", err)
	}

	plain := []byte("sign+encrypt combined streaming")
	ct, err := testCtx.SignEncryptUpdate(sh, plain)
	if err != nil {
		if errors.Is(err, Error(CKR_FUNCTION_NOT_SUPPORTED)) {
			t.Skipf("SignEncryptUpdate not supported by this module")
		}
		t.Fatalf("SignEncryptUpdate: %v", err)
	}
	tail, err := testCtx.EncryptFinal(sh)
	if err != nil {
		t.Fatalf("EncryptFinal: %v", err)
	}
	ciphertext := append(ct, tail...)
	sig, err := testCtx.SignFinal(sh)
	if err != nil {
		t.Fatalf("SignFinal: %v", err)
	}

	// Reverse: DecryptVerifyUpdate.
	if err := testCtx.VerifyInit(sh, NewMechanism(CKM_SHA256_RSA_PKCS, nil), pubH); err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	if err := testCtx.DecryptInit(sh, NewMechanism(CKM_AES_CBC_PAD, iv), encH); err != nil {
		t.Fatalf("DecryptInit: %v", err)
	}
	pt, err := testCtx.DecryptVerifyUpdate(sh, ciphertext)
	if err != nil {
		if errors.Is(err, Error(CKR_FUNCTION_NOT_SUPPORTED)) {
			t.Skipf("DecryptVerifyUpdate not supported by this module")
		}
		t.Fatalf("DecryptVerifyUpdate: %v", err)
	}
	ptTail, err := testCtx.DecryptFinal(sh)
	if err != nil {
		t.Fatalf("DecryptFinal: %v", err)
	}
	if err := testCtx.VerifyFinal(sh, sig); err != nil {
		t.Fatalf("VerifyFinal: %v", err)
	}

	plainGot := append(pt, ptTail...)
	if !bytes.Equal(plainGot, plain) {
		t.Fatalf("round-trip mismatch: got %q, want %q", plainGot, plain)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// genAESKeyRaw generates a copyable session AES-256 key and returns its handle.
func genAESKeyRaw(t *testing.T, sh SessionHandle, label string) (ObjectHandle, error) {
	t.Helper()
	return testCtx.GenerateKey(sh, NewMechanism(CKM_AES_KEY_GEN, nil), []*Attribute{
		NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
		NewAttribute(CKA_KEY_TYPE, uint(CKK_AES)),
		NewAttribute(CKA_VALUE_LEN, 32),
		NewAttribute(CKA_TOKEN, false),
		NewAttribute(CKA_LABEL, label),
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_DECRYPT, true),
		NewAttribute(CKA_COPYABLE, true),
	})
}

// genRSAKeyPairRaw generates a session RSA-2048 key pair and returns the
// public and private handles.
func genRSAKeyPairRaw(t *testing.T, sh SessionHandle) (ObjectHandle, ObjectHandle, error) {
	t.Helper()
	return testCtx.GenerateKeyPair(sh,
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
}
