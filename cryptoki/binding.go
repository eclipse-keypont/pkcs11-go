// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#cgo CFLAGS: -I${SRCDIR}/../internal/headers
#cgo linux LDFLAGS: -ldl
#cgo darwin LDFLAGS: -ldl

#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	_ "github.com/eclipse-keypont/pkcs11-go/internal/headers" // vendor anchor: ensures go mod vendor copies the C headers
)

// errClosed is returned by Ctx methods invoked after Destroy.
var errClosed = errors.New("cryptoki: module is closed")

// Ctx is a loaded PKCS #11 module. It wraps the module's CK_FUNCTION_LIST and
// dispatches Cryptoki calls to it. Obtain one with New and release it with
// Destroy. A Ctx is safe to share across goroutines only to the extent the
// underlying module is; initialise the module with OS locking (the default).
// Note that a single PKCS #11 session is a stateful state machine: concurrent
// operations on one SessionHandle must be serialised by the caller (the p11
// layer does this for you).
type Ctx struct {
	mu     sync.RWMutex
	module *C.ckModule
}

// New loads the PKCS #11 module shared object at path (e.g. a vendor driver or
// SoftHSM) and resolves its function list. It does not call C_Initialize; call
// Initialize next. The returned Ctx must be released with Destroy.
//
// path must be absolute. Loading a module runs its initialisers immediately
// (it is arbitrary native code by design), and a relative path would let the
// dynamic linker resolve it against search directories such as LD_LIBRARY_PATH
// or the current directory — a library-injection risk. Resolve the path
// yourself (e.g. from a trusted config) before calling New.
func New(path string) (*Ctx, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("cryptoki: module path must be absolute, got %q", path)
	}

	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	var rv C.CK_RV
	var errbuf [256]C.char
	m := C.ck_load(cpath, &rv, &errbuf[0], C.size_t(len(errbuf)))
	if m == nil {
		reason := C.GoString(&errbuf[0])
		if reason == "" {
			reason = "could not load module"
		}
		return nil, fmt.Errorf("cryptoki: loading %q: %s", path, reason)
	}
	return &Ctx{module: m}, nil
}

// grab acquires a read-lock and returns the module pointer plus its unlock
// func. Callers must defer the returned func. Returns errClosed if the module
// has been destroyed.
func (c *Ctx) grab() (*C.ckModule, func(), error) {
	c.mu.RLock()
	if c.module == nil {
		c.mu.RUnlock()
		return nil, nil, errClosed
	}
	return c.module, c.mu.RUnlock, nil
}

// Destroy unloads the module and closes the shared library. It does not call
// Finalize; call Finalize before Destroy. Destroy is idempotent.
func (c *Ctx) Destroy() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.module == nil {
		return
	}
	C.ck_unload(c.module)
	c.module = nil
}

// SupportsV32 reports whether the loaded module advertises the PKCS #11 v3.2
// interface (via C_GetInterface). The v3.2-only methods require this.
func (c *Ctx) SupportsV32() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.module != nil && C.ck_has_v32(c.module) != 0
}

// Wipe overwrites b with zeros. Call it on any Go-side buffer that held a PIN
// or key material once you are done with it. The runtime.KeepAlive keeps the
// compiler from eliding the writes if it can prove b is otherwise unused.
//
// Wipe reduces, but cannot eliminate, secret exposure in a garbage-collected
// runtime: the Go GC may already have copied b while moving the stack or
// growing a slice. For maximum assurance keep secrets inside the HSM (generate
// non-extractable, sensitive keys) so they never reach process memory.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// goVersion converts a C CK_VERSION into the exported Version type.
func goVersion(v C.CK_VERSION) Version {
	return Version{Major: byte(v.major), Minor: byte(v.minor)}
}

// goPaddedString converts a fixed-width, space-padded Cryptoki character field
// (CK_UTF8CHAR[n], not NUL-terminated) into a Go string with trailing spaces
// and NULs removed. p points at the first byte of the field, n is its length.
func goPaddedString(p unsafe.Pointer, n int) string {
	b := C.GoBytes(p, C.int(n))
	return string(bytes.TrimRight(b, " \x00"))
}
