/*
 * mock.c — a stand-in PKCS #11 module for the tests of an operation the
 * binding gives up on part-way (outOp).
 *
 * SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
 * SPDX-License-Identifier: MIT
 *
 * C_EncryptInit starts an encryption and answers CKR_OPERATION_ACTIVE while
 * one is active. The sizing pass of C_Encrypt reports an output one byte over
 * the binding's 64 MiB limit; with MOCK_TOO_SMALL it reports 16 bytes instead,
 * and every data pass answers CKR_BUFFER_TOO_SMALL. Either way the encryption
 * stays active, as the specification says it does.
 *
 * How the encryption can be ended depends on how the mock is compiled:
 *
 *   MOCK_CANCEL     C_SessionCancel(CKF_ENCRYPT) ends it
 *   MOCK_INIT_NULL  C_EncryptInit with a NULL mechanism ends it, as in v3.0
 *   MOCK_V2         no C_GetInterface, so a v2 module. A NULL mechanism still
 *                   ends the encryption, so a test can tell it was not used.
 *
 * Otherwise C_SessionCancel answers CKR_FUNCTION_NOT_SUPPORTED and a NULL
 * mechanism CKR_ARGUMENTS_BAD.
 */

#include <stddef.h>

#include "platform.h"

static int active;

static CK_RV EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                         CK_OBJECT_HANDLE hKey) {
	(void)hSession;
	(void)hKey;
	if (pMechanism == NULL_PTR) {
#if defined(MOCK_INIT_NULL) || defined(MOCK_V2)
		active = 0;
		return CKR_OK;
#else
		return CKR_ARGUMENTS_BAD;
#endif
	}
	if (active) {
		return CKR_OPERATION_ACTIVE;
	}
	active = 1;
	return CKR_OK;
}

static CK_RV Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                     CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen) {
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	if (!active) {
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	if (pulEncryptedDataLen == NULL_PTR) {
		active = 0;
		return CKR_ARGUMENTS_BAD;
	}
#if defined(MOCK_TOO_SMALL)
	*pulEncryptedDataLen = 16;
	return pEncryptedData == NULL_PTR ? CKR_OK : CKR_BUFFER_TOO_SMALL;
#else
	(void)pEncryptedData;
	*pulEncryptedDataLen = (CK_ULONG)(64 << 20) + 1;
	return CKR_OK;
#endif
}

static CK_RV SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags) {
	(void)hSession;
#if defined(MOCK_CANCEL)
	if (flags & CKF_ENCRYPT) {
		active = 0;
	}
	return CKR_OK;
#else
	(void)flags;
	return CKR_FUNCTION_NOT_SUPPORTED;
#endif
}

static CK_FUNCTION_LIST list20 = {{2, 40}};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
	if (ppFunctionList == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	list20.C_EncryptInit = EncryptInit;
	list20.C_Encrypt = Encrypt;
	*ppFunctionList = &list20;
	return CKR_OK;
}

#if !defined(MOCK_V2)
static CK_FUNCTION_LIST_3_2 list32 = {{3, 2}};
static CK_INTERFACE iface32 = {(CK_CHAR_PTR) "PKCS 11", &list32, 0};

CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
                     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags) {
	(void)pInterfaceName;
	(void)pVersion;
	(void)flags;
	if (ppInterface == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	list32.C_EncryptInit = EncryptInit;
	list32.C_Encrypt = Encrypt;
	list32.C_SessionCancel = SessionCancel;
	*ppInterface = &iface32;
	return CKR_OK;
}
#endif
