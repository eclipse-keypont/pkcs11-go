// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import "fmt"

// SeedRandom mixes additional seed material into the token's RNG
// (C_SeedRandom). Not all tokens support it.
func (c *Ctx) SeedRandom(sh SessionHandle, seed []byte) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	p, n := cBytes(seed)
	defer zfree(p, n)
	return toError(uint(C.ck_seed_random(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(p), n)))
}

// GenerateRandom returns length cryptographically random bytes from the token
// (C_GenerateRandom). length must be positive and no greater than maxOutBuf.
func (c *Ctx) GenerateRandom(sh SessionHandle, length int) ([]byte, error) {
	if length <= 0 {
		return []byte{}, nil
	}
	if length > maxOutBuf {
		return nil, fmt.Errorf("cryptoki: GenerateRandom: length %d exceeds limit %d", length, maxOutBuf)
	}
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	buf := C.malloc(C.size_t(length))
	defer zfree(buf, C.CK_ULONG(length))
	rv := C.ck_generate_random(m, C.CK_SESSION_HANDLE(sh), (C.CK_BYTE_PTR)(buf), C.CK_ULONG(length))
	if err := toError(uint(rv)); err != nil {
		return nil, err
	}
	return C.GoBytes(buf, C.int(length)), nil
}
