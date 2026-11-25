// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"bytes"
	"errors"
	"testing"
)

// TestIntegrationNestedTemplateRefused checks that a nested template given as
// raw bytes is refused by the binding, before the module sees it.
func TestIntegrationNestedTemplateRefused(t *testing.T) {
	sh := requireSession(t)
	for _, typ := range templateTypes {
		_, err := testCtx.CreateObject(sh, []*Attribute{
			NewAttribute(CKA_CLASS, uint(CKO_SECRET_KEY)),
			NewAttribute(CKA_KEY_TYPE, uint(CKK_AES)),
			NewAttribute(CKA_TOKEN, false),
			NewAttribute(CKA_VALUE, make([]byte, 32)),
			NewAttribute(typ, make([]byte, 64)),
		})
		var rv Error
		if err == nil || errors.As(err, &rv) {
			t.Errorf("CreateObject with %s = %v, want the binding to refuse it", AttributeName(typ), err)
		}
	}
}

// TestIntegrationReadAllowedMechanisms checks that CKA_ALLOWED_MECHANISMS, a
// flat array of mechanism types, can be read back.
func TestIntegrationReadAllowedMechanisms(t *testing.T) {
	sh := requireSession(t)
	allowed := append(ckULong(CKM_AES_GCM), ckULong(CKM_AES_CBC_PAD)...)
	key := genAESKey(t, sh, 256,
		NewAttribute(CKA_ENCRYPT, true),
		NewAttribute(CKA_ALLOWED_MECHANISMS, allowed))

	got, err := testCtx.GetAttributeValue(sh, key, []*Attribute{NewAttribute(CKA_ALLOWED_MECHANISMS, nil)})
	if err != nil {
		t.Fatalf("GetAttributeValue(CKA_ALLOWED_MECHANISMS): %v", err)
	}
	// The value is a set: a token may return the mechanisms in any order.
	w := len(ckULong(0))
	if len(got[0].Value) != len(allowed) {
		t.Fatalf("CKA_ALLOWED_MECHANISMS = %x, want the mechanisms in %x", got[0].Value, allowed)
	}
	for i := 0; i < len(allowed); i += w {
		if !bytes.Contains(got[0].Value, allowed[i:i+w]) {
			t.Fatalf("CKA_ALLOWED_MECHANISMS = %x, want the mechanisms in %x", got[0].Value, allowed)
		}
	}
}
