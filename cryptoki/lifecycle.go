// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include "shim.h"
*/
import "C"

import "unsafe"

// Initialize prepares the loaded module for use (C_Initialize) with OS thread
// locking (CKF_OS_LOCKING_OK), so the module is safe to call from multiple
// goroutines. Call it once after New and before any other operation. For finer
// control (or to share a module already initialised by another library in the
// process) use InitializeWithFlags.
func (c *Ctx) Initialize() error {
	return c.InitializeWithFlags(CKF_OS_LOCKING_OK)
}

// InitializeWithFlags calls C_Initialize with the given CK_C_INITIALIZE_ARGS
// flags. CKR_CRYPTOKI_ALREADY_INITIALIZED is reported as a typed error rather
// than swallowed, so a caller sharing the module can decide whether to treat it
// as success. A write-lock is held so that Initialize cannot race a concurrent
// operation or Finalize on the same Ctx.
func (c *Ctx) InitializeWithFlags(flags uint) error {
	if c == nil {
		return errClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.module == nil {
		return errClosed
	}
	rv := C.ck_initialize(c.module, C.CK_FLAGS(flags), nil)
	return toError(uint(rv))
}

// Finalize releases the module's resources (C_Finalize). Call it once when
// finished, before Destroy. It is safe to call after Destroy (returns
// errClosed rather than crashing). A write-lock is held so that Finalize
// cannot race a concurrent operation or Initialize on the same Ctx.
func (c *Ctx) Finalize() error {
	if c == nil {
		return errClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.module == nil {
		return errClosed
	}
	return toError(uint(C.ck_finalize(c.module)))
}

// GetInfo returns general information about the Cryptoki library (C_GetInfo).
func (c *Ctx) GetInfo() (Info, error) {
	m, release, err := c.grab()
	if err != nil {
		return Info{}, err
	}
	defer release()
	var ci C.alignedCKInfo
	if err := toError(uint(C.ck_get_info(m, &ci))); err != nil {
		return Info{}, err
	}
	return Info{
		CryptokiVersion:    goVersion(ci.cryptokiVersion),
		ManufacturerID:     goPaddedString(unsafe.Pointer(&ci.manufacturerID[0]), len(ci.manufacturerID)),
		Flags:              uint(ci.flags),
		LibraryDescription: goPaddedString(unsafe.Pointer(&ci.libraryDescription[0]), len(ci.libraryDescription)),
		LibraryVersion:     goVersion(ci.libraryVersion),
	}, nil
}
