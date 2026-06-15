/*
 * platform.h — Cryptoki platform-configuration shim.
 *
 * SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
 * SPDX-License-Identifier: MIT
 *
 * PKCS #11 requires the consumer to supply five platform-specific macros and a
 * structure-packing convention *before* including <pkcs11.h>. The required
 * macros and their typical Unix definitions are documented verbatim in the
 * header comment block at the top of the OASIS pkcs11.h. This file provides
 * those definitions for the cgo binding and then pulls in the unmodified OASIS
 * headers. It deliberately contains no PKCS #11 declarations of its own — only
 * the configuration the spec demands of every caller.
 *
 * Derived solely from the OASIS PKCS #11 v3.2 header documentation; it is not a
 * copy of any third-party Go binding's helper header.
 */

#ifndef ECLIPSE_KEYPONT_PKCS11_PLATFORM_H
#define ECLIPSE_KEYPONT_PKCS11_PLATFORM_H 1

/* 1. CK_PTR: the indirection string for making a pointer to an object. */
#define CK_PTR *

/* 2/3. Cryptoki function declarations/definitions. On Unix no special export
 *      decoration is needed, so the name is emitted as-is. */
#define CK_DECLARE_FUNCTION(returnType, name)         returnType name
#define CK_DEFINE_FUNCTION(returnType, name)          returnType name

/* 4. Pointer to a Cryptoki API function. */
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)

/* 5. Pointer to an application-supplied callback function. */
#define CK_CALLBACK_FUNCTION(returnType, name)        returnType (* name)

/* NULL_PTR: the null pointer value. */
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

/* Cryptoki mandates 1-byte structure packing (see the packing note at the top
 * of pkcs11.h). On Windows this packing is required for ABI compatibility with
 * loaded modules, so force it there unless the caller already asked for it.
 * On typical Unix ABIs the natural layout already matches, so packing is left
 * off to keep cgo field access straightforward. */
#if defined(_WIN32) && !defined(PACKED_STRUCTURES)
#  define PACKED_STRUCTURES 1
#endif

#ifdef PACKED_STRUCTURES
#  pragma pack(push, 1)
#  include "pkcs11.h"
#  pragma pack(pop)
#else
#  include "pkcs11.h"
#endif

/*
 * Naturally aligned mirror of CK_INFO.
 *
 * When the Cryptoki structures are byte-packed, Go's cgo refuses to expose
 * fields that fall on unaligned offsets. Reading CK_INFO therefore goes through
 * this default-aligned copy. The field layout is dictated by the spec's
 * definition of CK_INFO (§3.1).
 */
typedef struct alignedCKInfo {
	CK_VERSION  cryptokiVersion;
	CK_UTF8CHAR manufacturerID[32];
	CK_FLAGS    flags;
	CK_UTF8CHAR libraryDescription[32];
	CK_VERSION  libraryVersion;
} alignedCKInfo;

#endif /* ECLIPSE_KEYPONT_PKCS11_PLATFORM_H */
