// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package p11

import "github.com/eclipse-keypont/pkcs11-go/cryptoki"

// withSecureDefaults returns tmpl with secure-by-default attributes added for
// any the caller did not set explicitly (P11):
//
//   - CKA_SENSITIVE = true   — the key value cannot be read out
//   - CKA_EXTRACTABLE = false — the key cannot be wrapped/exported
//   - CKA_PRIVATE = true      — the object is only visible to an authenticated
//     user (private keys and secret keys)
//
// A caller that needs a different value sets the attribute itself; an explicit
// value always wins, so this only fills gaps. The returned slice is a new slice
// and never mutates the caller's.
func withSecureDefaults(tmpl []*cryptoki.Attribute, private bool) []*cryptoki.Attribute {
	out := make([]*cryptoki.Attribute, 0, len(tmpl)+3)
	out = append(out, tmpl...)

	if !hasAttribute(tmpl, cryptoki.CKA_SENSITIVE) {
		out = append(out, cryptoki.NewAttribute(cryptoki.CKA_SENSITIVE, true))
	}
	if !hasAttribute(tmpl, cryptoki.CKA_EXTRACTABLE) {
		out = append(out, cryptoki.NewAttribute(cryptoki.CKA_EXTRACTABLE, false))
	}
	if private && !hasAttribute(tmpl, cryptoki.CKA_PRIVATE) {
		out = append(out, cryptoki.NewAttribute(cryptoki.CKA_PRIVATE, true))
	}
	return out
}

// hasAttribute reports whether tmpl already sets the given attribute type.
func hasAttribute(tmpl []*cryptoki.Attribute, typ uint) bool {
	for _, a := range tmpl {
		if a != nil && a.Type == typ {
			return true
		}
	}
	return false
}
