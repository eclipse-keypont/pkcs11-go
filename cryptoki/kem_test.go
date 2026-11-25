// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"path/filepath"
	"testing"
)

// TestEncapsulateKeyRejectsEmptyCiphertext checks that an empty KEM
// ciphertext is an error, whether the sizing pass or the data pass reports
// it, and that a key the module created on the data pass is destroyed.
func TestEncapsulateKeyRejectsEmptyCiphertext(t *testing.T) {
	for _, c := range []struct {
		name    string
		defines []string
	}{
		{"SizingPass", nil},
		{"DataPass", []string{"MOCK_EMPTY_DATA_PASS"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, err := New(compileTestModule(t, filepath.Join("testdata", "kemmock", "mock.c"), c.defines...))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer ctx.Destroy()

			const sh, pub = SessionHandle(1), ObjectHandle(1)
			ct, key, err := ctx.EncapsulateKey(sh, NewMechanism(CKM_ML_KEM, nil), pub, nil)
			if err == nil {
				t.Fatalf("EncapsulateKey = (%x, %d), want an error for an empty ciphertext", ct, key)
			}
			if _, err := ctx.GetObjectSize(sh, 7); err == nil {
				t.Fatal("the key the module created is still there")
			}
		})
	}
}
