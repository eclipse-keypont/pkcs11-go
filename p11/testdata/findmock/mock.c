/*
 * mock.c — a stand-in PKCS #11 module whose object search never ends, for the
 * test of the bound on p11's FindObjects.
 *
 * SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
 * SPDX-License-Identifier: MIT
 *
 * It offers one slot and opens sessions on it. C_FindObjects fills every batch
 * it is asked for, so a caller that waits for an empty batch never sees one.
 */

#include <stddef.h>

#include "platform.h"

static CK_RV Initialize(CK_VOID_PTR pInitArgs) {
	(void)pInitArgs;
	return CKR_OK;
}

static CK_RV Finalize(CK_VOID_PTR pReserved) {
	(void)pReserved;
	return CKR_OK;
}

static CK_RV GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount) {
	(void)tokenPresent;
	if (pulCount == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	if (pSlotList != NULL_PTR) {
		if (*pulCount < 1) {
			*pulCount = 1;
			return CKR_BUFFER_TOO_SMALL;
		}
		pSlotList[0] = 0;
	}
	*pulCount = 1;
	return CKR_OK;
}

static CK_RV OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
                         CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession) {
	(void)slotID;
	(void)flags;
	(void)pApplication;
	(void)Notify;
	if (phSession == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	*phSession = 1;
	return CKR_OK;
}

static CK_RV CloseSession(CK_SESSION_HANDLE hSession) {
	(void)hSession;
	return CKR_OK;
}

static CK_RV FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                             CK_ULONG ulCount) {
	(void)hSession;
	(void)pTemplate;
	(void)ulCount;
	return CKR_OK;
}

static CK_RV FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
                         CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount) {
	(void)hSession;
	if (phObject == NULL_PTR || pulObjectCount == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	for (CK_ULONG i = 0; i < ulMaxObjectCount; i++) {
		phObject[i] = i + 1;
	}
	*pulObjectCount = ulMaxObjectCount;
	return CKR_OK;
}

static CK_RV FindObjectsFinal(CK_SESSION_HANDLE hSession) {
	(void)hSession;
	return CKR_OK;
}

static CK_FUNCTION_LIST list = {{2, 40}};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
	if (ppFunctionList == NULL_PTR) {
		return CKR_ARGUMENTS_BAD;
	}
	list.C_Initialize = Initialize;
	list.C_Finalize = Finalize;
	list.C_GetSlotList = GetSlotList;
	list.C_OpenSession = OpenSession;
	list.C_CloseSession = CloseSession;
	list.C_FindObjectsInit = FindObjectsInit;
	list.C_FindObjects = FindObjects;
	list.C_FindObjectsFinal = FindObjectsFinal;
	*ppFunctionList = &list;
	return CKR_OK;
}
