// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import "fmt"

// Error is a PKCS #11 return value (CK_RV) other than CKR_OK. Every Cryptoki
// call that fails reports its CK_RV as one of these. The symbolic CKR_ names
// are in the generated table ckrNames (see zerror.go).
type Error uint

// Error renders the return value as its CKR_ symbol when known, e.g.
// "pkcs11: CKR_PIN_INCORRECT", otherwise as a hex code.
func (e Error) Error() string {
	if name, ok := ckrNames[e]; ok {
		return "pkcs11: " + name
	}
	return fmt.Sprintf("pkcs11: 0x%08X", uint(e))
}

// toError maps a raw CK_RV into a Go error, returning nil for CKR_OK so that
// call sites can `return toError(rv)` directly.
func toError(rv uint) error {
	if rv == CKR_OK {
		return nil
	}
	return Error(rv)
}
