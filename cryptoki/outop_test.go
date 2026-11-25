// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"
)

// TestOutOpEndsAbandonedOperation checks that an operation the binding gives
// up on part-way, because the output is over the size limit or the module
// keeps answering CKR_BUFFER_TOO_SMALL, is ended on the session, so that the
// next C_EncryptInit succeeds; and that when it cannot be ended, the error
// wraps ErrOperationActive.
func TestOutOpEndsAbandonedOperation(t *testing.T) {
	cases := []struct {
		name        string
		defines     []string
		stillActive bool
	}{
		{"SessionCancel", []string{"MOCK_CANCEL"}, false},
		{"InitNullMechanism", []string{"MOCK_INIT_NULL"}, false},
		{"NeitherSupported", nil, true},
		// A v2 module is not asked to accept a NULL mechanism, although this
		// one would end the operation on it.
		{"V2Module", []string{"MOCK_V2"}, true},
		{"BufferTooSmall", []string{"MOCK_TOO_SMALL", "MOCK_CANCEL"}, false},
		{"BufferTooSmallNotEnded", []string{"MOCK_TOO_SMALL"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, err := New(compileTestModule(t, filepath.Join("testdata", "opmock", "mock.c"), c.defines...))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer ctx.Destroy()

			const sh, key = SessionHandle(1), ObjectHandle(1)
			mech := NewMechanism(CKM_AES_ECB, nil)
			if err := ctx.EncryptInit(sh, mech, key); err != nil {
				t.Fatalf("EncryptInit: %v", err)
			}
			_, err = ctx.Encrypt(sh, []byte("data"))
			if err == nil {
				t.Fatal("Encrypt succeeded, want an error")
			}
			wantTooLarge := !slices.Contains(c.defines, "MOCK_TOO_SMALL")
			if got := errors.Is(err, ErrOutputTooLarge); got != wantTooLarge {
				t.Fatalf("errors.Is(%v, ErrOutputTooLarge) = %v, want %v", err, got, wantTooLarge)
			}
			if got := errors.Is(err, ErrOperationActive); got != c.stillActive {
				t.Fatalf("errors.Is(%v, ErrOperationActive) = %v, want %v", err, got, c.stillActive)
			}

			err = ctx.EncryptInit(sh, mech, key)
			if c.stillActive {
				if !errors.Is(err, Error(CKR_OPERATION_ACTIVE)) {
					t.Fatalf("EncryptInit after an operation left active = %v, want CKR_OPERATION_ACTIVE", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("EncryptInit after the abandoned operation: %v", err)
			}
		})
	}
}

// TestIntegrationSessionCancel checks C_SessionCancel on a real token: it ends
// an active encryption, so a new one can start on the same session.
func TestIntegrationSessionCancel(t *testing.T) {
	sh := requireSession(t)
	key := genAESKey(t, sh, 128, NewAttribute(CKA_ENCRYPT, true))
	mech := NewMechanism(CKM_AES_ECB, nil)

	if err := testCtx.EncryptInit(sh, mech, key); err != nil {
		t.Fatalf("EncryptInit: %v", err)
	}
	err := testCtx.SessionCancel(sh, CKF_ENCRYPT)
	if errors.Is(err, Error(CKR_FUNCTION_NOT_SUPPORTED)) {
		t.Skipf("module does not support C_SessionCancel: %v", err)
	}
	if err != nil {
		t.Fatalf("SessionCancel: %v", err)
	}
	if err := testCtx.EncryptInit(sh, mech, key); err != nil {
		t.Fatalf("EncryptInit after SessionCancel: %v", err)
	}
	if _, err := testCtx.Encrypt(sh, make([]byte, 16)); err != nil {
		t.Fatalf("Encrypt after SessionCancel: %v", err)
	}
}

// TestIntegrationOversizeOutputEndsOperation encrypts an input whose
// ciphertext is over the binding's output limit. Encrypt must fail with
// ErrOutputTooLarge and leave the session usable, or, on a module that cannot
// end the operation, say so with ErrOperationActive.
func TestIntegrationOversizeOutputEndsOperation(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates more than 64 MiB")
	}
	sh := requireSession(t)
	key := genAESKey(t, sh, 256, NewAttribute(CKA_ENCRYPT, true))
	mech := NewMechanism(CKM_AES_ECB, nil)

	if err := testCtx.EncryptInit(sh, mech, key); err != nil {
		t.Fatalf("EncryptInit: %v", err)
	}
	_, err := testCtx.Encrypt(sh, make([]byte, maxOutBuf+16))
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("Encrypt of %d bytes = %v, want ErrOutputTooLarge", maxOutBuf+16, err)
	}

	next := testCtx.EncryptInit(sh, mech, key)
	if errors.Is(err, ErrOperationActive) {
		if !errors.Is(next, Error(CKR_OPERATION_ACTIVE)) {
			t.Fatalf("EncryptInit after ErrOperationActive = %v, want CKR_OPERATION_ACTIVE", next)
		}
		t.Logf("module could not end the operation: %v", err)
		return
	}
	if next != nil {
		t.Fatalf("EncryptInit after the oversize Encrypt: %v", next)
	}
	if _, err := testCtx.Encrypt(sh, make([]byte, 16)); err != nil {
		t.Fatalf("Encrypt after the oversize Encrypt: %v", err)
	}
}

// TestOutOpRejectsLengthOverCapacity checks that a data pass reporting more
// bytes than the capacity it was given is an error. When the sizing pass
// reports no output, outOp still allocates one byte, so a module reporting one
// byte would otherwise hand back a byte it never wrote.
func TestOutOpRejectsLengthOverCapacity(t *testing.T) {
	ctx, err := New(compileTestModule(t, filepath.Join("testdata", "opmock", "mock.c"), "MOCK_ZERO_THEN_ONE"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ctx.Destroy()

	const sh, key = SessionHandle(1), ObjectHandle(1)
	if err := ctx.EncryptInit(sh, NewMechanism(CKM_AES_ECB, nil), key); err != nil {
		t.Fatalf("EncryptInit: %v", err)
	}
	if out, err := ctx.Encrypt(sh, []byte("data")); err == nil {
		t.Fatalf("Encrypt = %x, want an error for a length over the 0-byte capacity", out)
	}
}
