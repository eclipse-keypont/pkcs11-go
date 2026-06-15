// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include "shim.h"
*/
import "C"

// GetOperationState saves the cryptographic-operation state of a session into
// an opaque byte blob (C_GetOperationState). The blob can later be passed to
// SetOperationState to restore the operation — useful for cloning an in-progress
// digest or encrypt across sessions.
func (c *Ctx) GetOperationState(sh SessionHandle) ([]byte, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	return outOp(func(out C.CK_BYTE_PTR, outLen *C.CK_ULONG) C.CK_RV {
		return C.ck_get_operation_state(m, C.CK_SESSION_HANDLE(sh), out, outLen)
	})
}

// SetOperationState restores a previously saved operation state
// (C_SetOperationState). Pass CK_INVALID_HANDLE (0) for either key handle when
// the corresponding key is embedded in the state blob or no such operation is
// being restored.
func (c *Ctx) SetOperationState(sh SessionHandle, state []byte, encKey, authKey ObjectHandle) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	sp, slen := cBytes(state)
	defer zfree(sp, slen)
	rv := C.ck_set_operation_state(m, C.CK_SESSION_HANDLE(sh),
		(C.CK_BYTE_PTR)(sp), slen,
		C.CK_OBJECT_HANDLE(encKey), C.CK_OBJECT_HANDLE(authKey))
	return toError(uint(rv))
}
