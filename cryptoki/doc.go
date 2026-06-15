// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

// Package cryptoki is a low-level Go binding for the OASIS PKCS #11 (Cryptoki)
// v3.2 cryptographic token interface.
//
// It wraps a PKCS #11 module (a shared library such as a vendor HSM driver or
// SoftHSM) closely, exposing the Cryptoki C API as Go methods on a Ctx while
// applying Go idiom where it improves safety and ergonomics. Higher-level
// helpers built on top of this package live in module path .../p11.
//
// The constant set in zconst.go is generated directly from the OASIS header
// pkcs11t.h by ./cmd/genconst; see internal/headers/NOTICE.md for the headers'
// provenance and license. This binding is an independent, clean-room
// implementation derived solely from the OASIS PKCS #11 v3.2 specification and
// its published C headers.
package cryptoki

//go:generate go run ../cmd/genconst -header ../internal/headers/pkcs11t.h -out zconst.go -errout zerror.go -pkg cryptoki
