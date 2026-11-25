// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"errors"
	"fmt"
)

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

// ErrOutputTooLarge is wrapped by the error a method returns when the module
// reports a result larger than the binding accepts (64 MiB). The result is not
// read. The binding then ends the operation on the session; when it cannot,
// the error also wraps ErrOperationActive.
var ErrOutputTooLarge = errors.New("cryptoki: output exceeds the size limit")

// ErrOperationActive is wrapped by the error a method returns when it stopped
// a token operation part-way and could not end it: the session still carries
// the operation, so the next C_*Init of the same kind on that session fails
// with CKR_OPERATION_ACTIVE. Close the session, or end the operation yourself.
//
// The binding ends an operation with C_SessionCancel, or failing that with the
// v3.0 convention of calling C_*Init with a NULL mechanism. Both are v3
// behaviour, so on a module without a v3.2 interface, or one that supports
// neither, the operation stays active.
var ErrOperationActive = errors.New("cryptoki: operation still active on the session")
