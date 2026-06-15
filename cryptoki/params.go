// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// MechanismParams is a structured mechanism parameter whose CK_*_PARAMS C
// struct contains pointers and therefore cannot be expressed as a flat byte
// slice. Build one with the New*Params constructors and pass it to
// NewMechanismWithParams.
//
// The interface is sealed (build is unexported): only this package provides
// implementations. build allocates the parameter, and any buffers it points
// at, in C memory and returns a free that releases all of them. It is called
// once per operation by cMechanism, so callers never manage the C memory.
type MechanismParams interface {
	build() (ptr unsafe.Pointer, length C.CK_ULONG, free func())
}

// ── AES-GCM (CK_GCM_PARAMS) ──────────────────────────────────────────────────

// GCMParams holds the CK_GCM_PARAMS block for an AES-GCM operation. Unlike the
// other MechanismParams implementations whose C memory is freed after the Init
// call, GCMParams keeps the C struct alive until Free is called explicitly. This
// is required for HSMs that write a token-generated IV back into pIv during
// C_Encrypt (UseGCMIVFromHSM / CloudHSM behaviour). Call IV after Encrypt to
// retrieve the written-back value; call Free once the operation is complete.
type GCMParams struct {
	mu  sync.Mutex
	gp  *C.CK_GCM_PARAMS
	iv  unsafe.Pointer
	aad unsafe.Pointer
}

// NewGCMParams returns the parameters for AES-GCM (CKM_AES_GCM): the IV/nonce,
// optional additional authenticated data, and the authentication tag length in
// bits (commonly 128). Pass a nil iv when the HSM generates the nonce itself
// (UseGCMIVFromHSM); the allocated pIv buffer will receive the token-written
// value and can be read back via IV after C_Encrypt returns.
//
// tagBits must be a byte-aligned length in (0, 128]. A zero or out-of-range tag
// length is rejected with a panic: some modules would otherwise accept it and
// produce effectively unauthenticated ciphertext, which is a silent security
// failure rather than a recoverable runtime error.
func NewGCMParams(iv, aad []byte, tagBits int) *GCMParams {
	if tagBits <= 0 || tagBits > 128 || tagBits%8 != 0 {
		panic(fmt.Sprintf("cryptoki: NewGCMParams: tagBits must be byte-aligned in (0,128], got %d", tagBits))
	}
	gp := (*C.CK_GCM_PARAMS)(C.malloc(C.size_t(unsafe.Sizeof(C.CK_GCM_PARAMS{}))))
	ivPtr, ivLen := cBytes(iv)
	aadPtr, aadLen := cBytes(aad)
	gp.pIv = (C.CK_BYTE_PTR)(ivPtr)
	gp.ulIvLen = ivLen
	gp.ulIvBits = C.CK_ULONG(len(iv) * 8)
	gp.pAAD = (C.CK_BYTE_PTR)(aadPtr)
	gp.ulAADLen = aadLen
	gp.ulTagBits = C.CK_ULONG(tagBits)
	return &GCMParams{gp: gp, iv: ivPtr, aad: aadPtr}
}

// NewGCMParamsHSMIV returns GCM parameters for operations where the HSM
// generates the IV itself (UseGCMIVFromHSM / CloudHSM behaviour). A zeroed
// pIv buffer of ivLen bytes is pre-allocated so the token has somewhere to
// write the nonce back. ivLen must be positive (AES-GCM typically uses 12).
// Call IV after C_Encrypt to retrieve the written-back value; call Free once
// the operation is complete.
func NewGCMParamsHSMIV(ivLen int, aad []byte, tagBits int) *GCMParams {
	if tagBits <= 0 || tagBits > 128 || tagBits%8 != 0 {
		panic(fmt.Sprintf("cryptoki: NewGCMParamsHSMIV: tagBits must be byte-aligned in (0,128], got %d", tagBits))
	}
	if ivLen <= 0 {
		panic(fmt.Sprintf("cryptoki: NewGCMParamsHSMIV: ivLen must be positive, got %d", ivLen))
	}
	gp := (*C.CK_GCM_PARAMS)(C.malloc(C.size_t(unsafe.Sizeof(C.CK_GCM_PARAMS{}))))
	ivPtr := C.malloc(C.size_t(ivLen))
	C.ck_memzero(ivPtr, C.size_t(ivLen))
	aadPtr, aadLen := cBytes(aad)
	gp.pIv = (C.CK_BYTE_PTR)(ivPtr)
	gp.ulIvLen = C.CK_ULONG(ivLen)
	gp.ulIvBits = C.CK_ULONG(ivLen * 8)
	gp.pAAD = (C.CK_BYTE_PTR)(aadPtr)
	gp.ulAADLen = aadLen
	gp.ulTagBits = C.CK_ULONG(tagBits)
	return &GCMParams{gp: gp, iv: ivPtr, aad: aadPtr}
}

// build implements MechanismParams. The returned free func is a no-op; call
// Free explicitly once the full operation (Init + Encrypt/Decrypt) is done.
// Panics if called after Free.
func (p *GCMParams) build() (unsafe.Pointer, C.CK_ULONG, func()) {
	if p.gp == nil {
		panic("cryptoki: GCMParams.build called after Free")
	}
	return unsafe.Pointer(p.gp), C.CK_ULONG(unsafe.Sizeof(C.CK_GCM_PARAMS{})), func() {}
}

// IV reads the IV currently stored in the C pIv buffer. After C_Encrypt on an
// HSM that generates its own nonce, this returns the token-written value.
func (p *GCMParams) IV() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gp == nil || p.gp.pIv == nil || p.gp.ulIvLen == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(p.gp.pIv), C.int(p.gp.ulIvLen))
}

// Free releases the C memory. Safe to call more than once. Must be called
// after C_Encrypt or C_Decrypt (and any IV read-back via IV) is complete.
func (p *GCMParams) Free() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gp == nil {
		return
	}
	ivLen := p.gp.ulIvLen
	aadLen := p.gp.ulAADLen
	zfree(p.iv, ivLen)
	p.iv = nil
	zfree(p.aad, aadLen)
	p.aad = nil
	C.free(unsafe.Pointer(p.gp))
	p.gp = nil
}

// ── RSA-OAEP (CK_RSA_PKCS_OAEP_PARAMS) ───────────────────────────────────────

type oaepParams struct {
	hashAlg    uint
	mgf        uint
	source     uint
	sourceData []byte
}

// NewOAEPParams returns the parameters for RSA-OAEP (CKM_RSA_PKCS_OAEP):
// the hash mechanism (e.g. CKM_SHA256), the MGF (e.g. CKG_MGF1_SHA256), the
// source type (CKZ_DATA_SPECIFIED, or 0 with nil sourceData for none) and any
// label/source bytes.
func NewOAEPParams(hashAlg, mgf, source uint, sourceData []byte) MechanismParams {
	return &oaepParams{hashAlg: hashAlg, mgf: mgf, source: source, sourceData: sourceData}
}

func (p *oaepParams) build() (unsafe.Pointer, C.CK_ULONG, func()) {
	op := (*C.CK_RSA_PKCS_OAEP_PARAMS)(C.malloc(C.size_t(unsafe.Sizeof(C.CK_RSA_PKCS_OAEP_PARAMS{}))))
	src, srcLen := cBytes(p.sourceData)
	op.hashAlg = C.CK_MECHANISM_TYPE(p.hashAlg)
	op.mgf = C.CK_RSA_PKCS_MGF_TYPE(p.mgf)
	op.source = C.CK_RSA_PKCS_OAEP_SOURCE_TYPE(p.source)
	op.pSourceData = C.CK_VOID_PTR(src)
	op.ulSourceDataLen = srcLen
	return unsafe.Pointer(op), C.CK_ULONG(unsafe.Sizeof(C.CK_RSA_PKCS_OAEP_PARAMS{})), func() {
		free(src)
		C.free(unsafe.Pointer(op))
	}
}

// ── RSA-PSS (CK_RSA_PKCS_PSS_PARAMS) ─────────────────────────────────────────

type pssParams struct {
	hashAlg uint
	mgf     uint
	saltLen int
}

// NewPSSParams returns the parameters for RSA-PSS signatures (e.g.
// CKM_SHA256_RSA_PKCS_PSS): the hash mechanism, the MGF, and the salt length in
// bytes. The underlying C struct has no pointers, but a typed constructor keeps
// usage consistent with the other parameter kinds.
func NewPSSParams(hashAlg, mgf uint, saltLen int) MechanismParams {
	return &pssParams{hashAlg: hashAlg, mgf: mgf, saltLen: saltLen}
}

func (p *pssParams) build() (unsafe.Pointer, C.CK_ULONG, func()) {
	pp := (*C.CK_RSA_PKCS_PSS_PARAMS)(C.malloc(C.size_t(unsafe.Sizeof(C.CK_RSA_PKCS_PSS_PARAMS{}))))
	pp.hashAlg = C.CK_MECHANISM_TYPE(p.hashAlg)
	pp.mgf = C.CK_RSA_PKCS_MGF_TYPE(p.mgf)
	pp.sLen = C.CK_ULONG(p.saltLen)
	return unsafe.Pointer(pp), C.CK_ULONG(unsafe.Sizeof(C.CK_RSA_PKCS_PSS_PARAMS{})), func() {
		C.free(unsafe.Pointer(pp))
	}
}

// ── ECDH1 derive (CK_ECDH1_DERIVE_PARAMS) ────────────────────────────────────

type ecdh1Params struct {
	kdf        uint
	sharedData []byte
	publicData []byte
}

// NewECDH1DeriveParams returns the parameters for ECDH1 key derivation
// (CKM_ECDH1_DERIVE): the key-derivation function (e.g. CKD_NULL), optional
// shared data, and the other party's public EC point (publicData).
func NewECDH1DeriveParams(kdf uint, sharedData, publicData []byte) MechanismParams {
	return &ecdh1Params{kdf: kdf, sharedData: sharedData, publicData: publicData}
}

func (p *ecdh1Params) build() (unsafe.Pointer, C.CK_ULONG, func()) {
	ep := (*C.CK_ECDH1_DERIVE_PARAMS)(C.malloc(C.size_t(unsafe.Sizeof(C.CK_ECDH1_DERIVE_PARAMS{}))))
	shared, sharedLen := cBytes(p.sharedData)
	public, publicLen := cBytes(p.publicData)
	ep.kdf = C.CK_EC_KDF_TYPE(p.kdf)
	ep.pSharedData = (C.CK_BYTE_PTR)(shared)
	ep.ulSharedDataLen = sharedLen
	ep.pPublicData = (C.CK_BYTE_PTR)(public)
	ep.ulPublicDataLen = publicLen
	return unsafe.Pointer(ep), C.CK_ULONG(unsafe.Sizeof(C.CK_ECDH1_DERIVE_PARAMS{})), func() {
		zfree(shared, sharedLen)
		free(public)
		C.free(unsafe.Pointer(ep))
	}
}
