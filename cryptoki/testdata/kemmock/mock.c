/*
 * mock.c — a stand-in PKCS #11 module whose C_EncapsulateKey reports an empty
 * ciphertext, for the tests of the binding's checks on a KEM result.
 *
 * SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
 * SPDX-License-Identifier: MIT
 *
 * The sizing pass reports an empty ciphertext, or 16 bytes with
 * MOCK_EMPTY_DATA_PASS. The data pass, given a buffer, creates a key and
 * reports an empty ciphertext. C_GetObjectSize answers for that key only while
 * it exists, so a test can tell whether it was created and destroyed.
 */

#include <stddef.h>

#include "platform.h"

#define MOCK_KEY 7

static int created;
static int destroyed;

static CK_RV EncapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                            CK_OBJECT_HANDLE hPublicKey, CK_ATTRIBUTE_PTR pTemplate,
                            CK_ULONG ulAttributeCount, CK_BYTE_PTR pCiphertext,
                            CK_ULONG_PTR pulCiphertextLen, CK_OBJECT_HANDLE_PTR phKey) {
	(void)hSession;
	(void)pMechanism;
	(void)hPublicKey;
	(void)pTemplate;
	(void)ulAttributeCount;
	if (pulCiphertextLen == NULL_PTR || phKey == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	if (pCiphertext == NULL_PTR) {
#if defined(MOCK_EMPTY_DATA_PASS)
		*pulCiphertextLen = 16;
#else
		*pulCiphertextLen = 0;
#endif
		return CKR_OK;
	}
	*pulCiphertextLen = 0;
	*phKey = MOCK_KEY;
	created = 1;
	return CKR_OK;
}

static CK_RV DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject) {
	(void)hSession;
	if (hObject == MOCK_KEY && created) {
		destroyed = 1;
	}
	return CKR_OK;
}

static CK_RV GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                           CK_ULONG_PTR pulSize) {
	(void)hSession;
	if (pulSize == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	if (hObject != MOCK_KEY || !created || destroyed) {
		return CKR_OBJECT_HANDLE_INVALID;
	}
	*pulSize = 32;
	return CKR_OK;
}

static CK_FUNCTION_LIST list20 = {{2, 40}};
static CK_FUNCTION_LIST_3_2 list32 = {{3, 2}};
static CK_INTERFACE iface32 = {(CK_CHAR_PTR) "PKCS 11", &list32, 0};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
	if (ppFunctionList == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	*ppFunctionList = &list20;
	return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags) {
	(void)pInterfaceName;
	(void)pVersion;
	(void)flags;
	if (ppInterface == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	list32.C_EncapsulateKey = EncapsulateKey;
	list32.C_DestroyObject = DestroyObject;
	list32.C_GetObjectSize = GetObjectSize;
	*ppInterface = &iface32;
	return CKR_OK;
}
