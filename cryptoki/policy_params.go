// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include "shim.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// This file lets the mechanism policy see the digests named inside a raw
// Parameter, the bytes of a CK_*_PARAMS struct a caller built themselves. The
// structured MechanismParams report their digests through hashMechanisms; a
// raw parameter is decoded here, using the C struct layouts of the platform the
// binding is built for. Only digest fields are read, never a pointer.

// rawField is a field of a CK_*_PARAMS struct that names a digest: its offset,
// and how its value maps to the digest mechanism the policy judges.
type rawField struct {
	offset uintptr
	digest func(v uint) (uint, bool)
}

// rawLayout describes a CK_*_PARAMS struct for the policy. A parameter shorter
// than size cannot be decoded. behindPointer marks a struct whose digests sit
// in a nested struct reached through a pointer, which is never followed.
type rawLayout struct {
	size          uintptr
	fields        []rawField
	behindPointer bool
}

func digestAsIs(v uint) (uint, bool) { return v, true }

func digestOfMGF(v uint) (uint, bool) {
	h, ok := mgfHash[v]
	return h, ok
}

func digestOfKDF(v uint) (uint, bool) {
	h, ok := kdfHash[v]
	return h, ok
}

var (
	oaepLayout = rawLayout{
		size: unsafe.Sizeof(C.CK_RSA_PKCS_OAEP_PARAMS{}),
		fields: []rawField{
			{unsafe.Offsetof(C.CK_RSA_PKCS_OAEP_PARAMS{}.hashAlg), digestAsIs},
			{unsafe.Offsetof(C.CK_RSA_PKCS_OAEP_PARAMS{}.mgf), digestOfMGF},
		},
	}
	pssLayout = rawLayout{
		size: unsafe.Sizeof(C.CK_RSA_PKCS_PSS_PARAMS{}),
		fields: []rawField{
			{unsafe.Offsetof(C.CK_RSA_PKCS_PSS_PARAMS{}.hashAlg), digestAsIs},
			{unsafe.Offsetof(C.CK_RSA_PKCS_PSS_PARAMS{}.mgf), digestOfMGF},
		},
	}
	ecdh1Layout = rawLayout{
		size:   unsafe.Sizeof(C.CK_ECDH1_DERIVE_PARAMS{}),
		fields: []rawField{{unsafe.Offsetof(C.CK_ECDH1_DERIVE_PARAMS{}.kdf), digestOfKDF}},
	}
	ecmqvLayout = rawLayout{
		size:   unsafe.Sizeof(C.CK_ECMQV_DERIVE_PARAMS{}),
		fields: []rawField{{unsafe.Offsetof(C.CK_ECMQV_DERIVE_PARAMS{}.kdf), digestOfKDF}},
	}
	ecdhAESWrapLayout = rawLayout{
		size:   unsafe.Sizeof(C.CK_ECDH_AES_KEY_WRAP_PARAMS{}),
		fields: []rawField{{unsafe.Offsetof(C.CK_ECDH_AES_KEY_WRAP_PARAMS{}.kdf), digestOfKDF}},
	}
	rsaAESWrapLayout = rawLayout{
		size:          unsafe.Sizeof(C.CK_RSA_AES_KEY_WRAP_PARAMS{}),
		behindPointer: true,
	}
	hkdfLayout = rawLayout{
		size:   unsafe.Sizeof(C.CK_HKDF_PARAMS{}),
		fields: []rawField{{unsafe.Offsetof(C.CK_HKDF_PARAMS{}.prfHashMechanism), digestAsIs}},
	}
	// The PRF of an SP 800-108 KDF is a MAC mechanism (CKM_SHA256_HMAC,
	// CKM_AES_CMAC, ...), which the policy judges as it is.
	sp800108Layout = rawLayout{
		size:   unsafe.Sizeof(C.CK_SP800_108_KDF_PARAMS{}),
		fields: []rawField{{unsafe.Offsetof(C.CK_SP800_108_KDF_PARAMS{}.prfType), digestAsIs}},
	}
	sp800108FeedbackLayout = rawLayout{
		size:   unsafe.Sizeof(C.CK_SP800_108_FEEDBACK_KDF_PARAMS{}),
		fields: []rawField{{unsafe.Offsetof(C.CK_SP800_108_FEEDBACK_KDF_PARAMS{}.prfType), digestAsIs}},
	}
	hashSignLayout = rawLayout{
		size:   unsafe.Sizeof(C.CK_HASH_SIGN_ADDITIONAL_CONTEXT{}),
		fields: []rawField{{unsafe.Offsetof(C.CK_HASH_SIGN_ADDITIONAL_CONTEXT{}.hash), digestAsIs}},
	}
)

// rawLayouts maps each mechanism whose parameter names a digest to the layout
// of that parameter.
var rawLayouts = map[uint]rawLayout{
	CKM_RSA_PKCS_OAEP:                 oaepLayout,
	CKM_RSA_PKCS_PSS:                  pssLayout,
	CKM_SHA1_RSA_PKCS_PSS:             pssLayout,
	CKM_SHA224_RSA_PKCS_PSS:           pssLayout,
	CKM_SHA256_RSA_PKCS_PSS:           pssLayout,
	CKM_SHA384_RSA_PKCS_PSS:           pssLayout,
	CKM_SHA512_RSA_PKCS_PSS:           pssLayout,
	CKM_SHA3_224_RSA_PKCS_PSS:         pssLayout,
	CKM_SHA3_256_RSA_PKCS_PSS:         pssLayout,
	CKM_SHA3_384_RSA_PKCS_PSS:         pssLayout,
	CKM_SHA3_512_RSA_PKCS_PSS:         pssLayout,
	CKM_ECDH1_DERIVE:                  ecdh1Layout,
	CKM_ECDH1_COFACTOR_DERIVE:         ecdh1Layout,
	CKM_ECMQV_DERIVE:                  ecmqvLayout,
	CKM_ECDH_AES_KEY_WRAP:             ecdhAESWrapLayout,
	CKM_ECDH_X_AES_KEY_WRAP:           ecdhAESWrapLayout,
	CKM_ECDH_COF_AES_KEY_WRAP:         ecdhAESWrapLayout,
	CKM_RSA_AES_KEY_WRAP:              rsaAESWrapLayout,
	CKM_HKDF_DERIVE:                   hkdfLayout,
	CKM_HKDF_DATA:                     hkdfLayout,
	CKM_SP800_108_COUNTER_KDF:         sp800108Layout,
	CKM_SP800_108_DOUBLE_PIPELINE_KDF: sp800108Layout,
	CKM_SP800_108_FEEDBACK_KDF:        sp800108FeedbackLayout,
	CKM_HASH_ML_DSA:                   hashSignLayout,
	CKM_HASH_SLH_DSA:                  hashSignLayout,
}

// rawParamDigests returns the digest mechanisms that the raw parameter p of
// mechanism names, for the policy to judge. A mechanism whose parameter names
// none returns nil. It fails closed: a parameter too short for its struct, or
// one whose digests sit behind a pointer, is an error rather than a pass.
func rawParamDigests(mechanism uint, p []byte) ([]uint, error) {
	l, ok := rawLayouts[mechanism]
	if !ok {
		return nil, nil
	}
	if l.behindPointer {
		return nil, fmt.Errorf("cryptoki: mechanism %#x: the policy cannot check the digests of a raw parameter, which sit behind a pointer", mechanism)
	}
	if uintptr(len(p)) < l.size {
		return nil, fmt.Errorf("cryptoki: mechanism %#x: the policy cannot check the digests of a %d-byte parameter, want %d bytes", mechanism, len(p), l.size)
	}
	var digests []uint
	for _, f := range l.fields {
		if d, ok := f.digest(ulongAt(p, f.offset)); ok {
			digests = append(digests, d)
		}
	}
	return digests, nil
}

// ulongAt reads the native CK_ULONG at offset off of p, the inverse of
// ckULong. It copies the bytes, so p need not be aligned.
func ulongAt(p []byte, off uintptr) uint {
	var v C.CK_ULONG
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&v)), unsafe.Sizeof(v)), p[off:])
	return uint(v)
}
