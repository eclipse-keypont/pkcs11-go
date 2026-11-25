/*
 * mock.c — a stand-in PKCS #11 module that reports counts and lengths larger
 * than the buffers it is given, for the tests of the binding's bounds.
 *
 * SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
 * SPDX-License-Identifier: MIT
 *
 * C_GetSlotList and C_GetMechanismList report one entry on the sizing pass and
 * four on the second. C_FindObjects reports one object more than it was asked
 * for. C_GetAttributeValue reports a length no allocation can satisfy. None of
 * them writes to the buffers, so only the binding's checks are exercised.
 */

#include <stddef.h>

#include "platform.h"

static CK_RV GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
	(void)tokenPresent;
	if (pulCount == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	*pulCount = pSlotList == NULL_PTR ? 1 : 4;
	return CKR_OK;
}

static CK_RV GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
                              CK_ULONG_PTR pulCount) {
	(void)slotID;
	if (pulCount == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	*pulCount = pMechanismList == NULL_PTR ? 1 : 4;
	return CKR_OK;
}

static CK_RV FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                         CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
	(void)hSession;
	(void)phObject;
	if (pulObjectCount == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	*pulObjectCount = ulMaxObjectCount + 1;
	return CKR_OK;
}

static CK_RV GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                               CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
	(void)hSession;
	(void)hObject;
	for (CK_ULONG i = 0; i < ulCount; i++) {
		pTemplate[i].ulValueLen = (CK_ULONG)1 << (sizeof(CK_ULONG) * 8 - 2);
	}
	return CKR_OK;
}

static CK_FUNCTION_LIST list = {{2, 40}};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
	if (ppFunctionList == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	list.C_GetSlotList = GetSlotList;
	list.C_GetMechanismList = GetMechanismList;
	list.C_FindObjects = FindObjects;
	list.C_GetAttributeValue = GetAttributeValue;
	*ppFunctionList = &list;
	return CKR_OK;
}
