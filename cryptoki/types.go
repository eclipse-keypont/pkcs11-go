// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import "fmt"

// Handle aliases for the opaque identifiers Cryptoki hands back. They are
// distinct named types so the compiler keeps slot, session, and object handles
// from being mixed up at call sites.
type (
	// SlotID identifies a slot in the system (CK_SLOT_ID).
	SlotID uint

	// SessionHandle identifies an open session on a token (CK_SESSION_HANDLE).
	SessionHandle uint

	// ObjectHandle identifies an object within a session (CK_OBJECT_HANDLE).
	ObjectHandle uint
)

// Version is a Cryptoki version pair (CK_VERSION): a major and minor number,
// each in the range 0–255. The minor number is a two-digit fraction, so minor
// 10 means ".10", not ".1".
type Version struct {
	Major byte
	Minor byte
}

// String renders the version as "major.minor", e.g. "3.2".
func (v Version) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// Info describes a Cryptoki library (CK_INFO), as returned by Ctx.GetInfo.
// The fixed-width character fields of the C struct are exposed here as Go
// strings with their trailing space padding removed.
type Info struct {
	CryptokiVersion    Version // Cryptoki interface version
	ManufacturerID     string  // library manufacturer
	Flags              uint    // bit flags, reserved by the spec (currently none)
	LibraryDescription string  // human-readable library description
	LibraryVersion     Version // library implementation version
}

// Mechanism names a cryptographic mechanism (CK_MECHANISM) together with its
// optional parameter block.
//
// For mechanisms whose parameter is plain bytes (an IV, or an all-CK_ULONG
// struct), set Parameter via NewMechanism. For mechanisms whose CK_*_PARAMS
// struct contains pointers (GCM, OAEP, ECDH1, …), use NewMechanismWithParams
// with one of the MechanismParams constructors, which marshal the nested C
// memory correctly.
type Mechanism struct {
	Mechanism uint
	Parameter []byte
	params    MechanismParams // structured, pointer-bearing parameter, or nil
}

// NewMechanism returns a Mechanism for the given CKM_ identifier. Pass a nil
// parameter for mechanisms that take none; otherwise pass the raw parameter
// bytes (e.g. a CBC IV).
func NewMechanism(mechanism uint, parameter []byte) *Mechanism {
	return &Mechanism{Mechanism: mechanism, Parameter: parameter}
}

// NewMechanismWithParams returns a Mechanism whose parameter is a structured
// CK_*_PARAMS value built by one of the NewGCMParams / NewOAEPParams /
// NewECDH1DeriveParams / NewPSSParams constructors.
func NewMechanismWithParams(mechanism uint, params MechanismParams) *Mechanism {
	return &Mechanism{Mechanism: mechanism, params: params}
}

// Attribute is one object attribute (CK_ATTRIBUTE): a CKA_ type and its raw
// value bytes. A nil Value requests the attribute's length or marks it absent,
// matching Cryptoki's pValue == NULL convention.
type Attribute struct {
	Type  uint
	Value []byte
}
