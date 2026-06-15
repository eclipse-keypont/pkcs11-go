// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorString(t *testing.T) {
	if got := Error(CKR_PIN_INCORRECT).Error(); !strings.Contains(got, "CKR_PIN_INCORRECT") {
		t.Fatalf("known code: got %q, want it to mention CKR_PIN_INCORRECT", got)
	}
	if got := Error(0x7FFFFFFF).Error(); !strings.Contains(got, "0x7FFFFFFF") {
		t.Fatalf("unknown code: got %q, want a hex rendering", got)
	}
	if err := toError(CKR_OK); err != nil {
		t.Fatalf("CKR_OK should map to nil, got %v", err)
	}
}

func TestNewBadPath(t *testing.T) {
	_, err := New("/nonexistent/definitely-not-a-pkcs11-module.so")
	if err == nil {
		t.Fatal("expected an error loading a nonexistent module")
	}
	// A dynamic-loader failure is a plain Go error, not a Cryptoki CK_RV.
	var ckErr Error
	if errors.As(err, &ckErr) {
		t.Fatalf("loader failure should not surface as a CK_RV: %v", err)
	}
	if !strings.Contains(err.Error(), "cryptoki: loading") {
		t.Fatalf("unexpected error shape: %v", err)
	}
}
