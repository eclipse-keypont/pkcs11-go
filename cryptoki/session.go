// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include "shim.h"
*/
import "C"

// SessionInfo describes an open session (CK_SESSION_INFO), from GetSessionInfo.
type SessionInfo struct {
	SlotID      SlotID
	State       uint // one of the CKS_ session states
	Flags       uint // CKF_SERIAL_SESSION, CKF_RW_SESSION, …
	DeviceError uint // device-dependent error code
}

// OpenSession opens a session with a token in a slot (C_OpenSession). flags must
// include CKF_SERIAL_SESSION; add CKF_RW_SESSION for a read/write session.
func (c *Ctx) OpenSession(slot SlotID, flags uint) (SessionHandle, error) {
	m, release, err := c.grab()
	if err != nil {
		return 0, err
	}
	defer release()
	var sh C.CK_SESSION_HANDLE
	rv := C.ck_open_session(m, C.CK_SLOT_ID(slot), C.CK_FLAGS(flags), &sh)
	if err := toError(uint(rv)); err != nil {
		return 0, err
	}
	return SessionHandle(sh), nil
}

// CloseSession closes a session (C_CloseSession).
func (c *Ctx) CloseSession(sh SessionHandle) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	return toError(uint(C.ck_close_session(m, C.CK_SESSION_HANDLE(sh))))
}

// CloseAllSessions closes every session a token in a slot has open
// (C_CloseAllSessions).
func (c *Ctx) CloseAllSessions(slot SlotID) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	return toError(uint(C.ck_close_all_sessions(m, C.CK_SLOT_ID(slot))))
}

// GetSessionInfo returns information about a session (C_GetSessionInfo).
func (c *Ctx) GetSessionInfo(sh SessionHandle) (SessionInfo, error) {
	m, release, err := c.grab()
	if err != nil {
		return SessionInfo{}, err
	}
	defer release()
	var info C.CK_SESSION_INFO
	if err := toError(uint(C.ck_get_session_info(m, C.CK_SESSION_HANDLE(sh), &info))); err != nil {
		return SessionInfo{}, err
	}
	return SessionInfo{
		SlotID:      SlotID(info.slotID),
		State:       uint(info.state),
		Flags:       uint(info.flags),
		DeviceError: uint(info.ulDeviceError),
	}, nil
}

// Login logs a user into a token on a session (C_Login). userType is typically
// CKU_USER or CKU_SO. The PIN is taken as a []byte so the caller can wipe it
// after use (see Wipe); the C-side copy is scrubbed before being freed.
func (c *Ctx) Login(sh SessionHandle, userType uint, pin []byte) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	p, n := cBytes(pin)
	defer zfree(p, n)
	rv := C.ck_login(m, C.CK_SESSION_HANDLE(sh), C.CK_USER_TYPE(userType),
		(C.CK_UTF8CHAR_PTR)(p), n)
	return toError(uint(rv))
}

// Logout logs the current user out of a session's token (C_Logout).
func (c *Ctx) Logout(sh SessionHandle) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	return toError(uint(C.ck_logout(m, C.CK_SESSION_HANDLE(sh))))
}
