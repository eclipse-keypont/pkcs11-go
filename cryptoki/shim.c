/*
 * shim.c — dynamic loader and CK_FUNCTION_LIST dispatch for the Go binding.
 *
 * SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
 * SPDX-License-Identifier: MIT
 *
 * Original implementation derived from the OASIS PKCS #11 v3.2 specification
 * (module loading via C_GetFunctionList / C_GetInterface) and the platform
 * dynamic-linker APIs. No third-party binding code is reused.
 */

#include "shim.h"

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <dlfcn.h>
#endif

/* Local function-pointer types for the two module entry points we resolve by
 * name. Declaring them here keeps the shim independent of whichever spelling
 * the header uses for these typedefs. */
typedef CK_RV (*ck_get_function_list_fn)(CK_FUNCTION_LIST_PTR_PTR);
typedef CK_RV (*ck_get_interface_fn)(CK_UTF8CHAR_PTR, CK_VERSION_PTR,
                                     CK_INTERFACE_PTR_PTR, CK_FLAGS);

struct ckModule {
	void *dl;                       /* dlopen / LoadLibrary handle */
	CK_FUNCTION_LIST_PTR fns;       /* base 2.x function list (always set) */
	CK_FUNCTION_LIST_3_2_PTR fns32; /* 3.2 function list, or NULL */
};

/* Resolve a symbol by name across platforms. */
static void *ck_sym(void *dl, const char *name) {
#if defined(_WIN32)
	return (void *)GetProcAddress((HMODULE)dl, name);
#else
	return dlsym(dl, name);
#endif
}

/* Copy a NUL-terminated reason into errbuf, truncating to errlen. Safe to call
 * with a NULL or zero-length buffer. */
static void ck_set_err(char *errbuf, size_t errlen, const char *msg) {
	if (errbuf == NULL || errlen == 0) {
		return;
	}
	if (msg == NULL) {
		msg = "unknown error";
	}
	size_t n = strlen(msg);
	if (n >= errlen) {
		n = errlen - 1;
	}
	memcpy(errbuf, msg, n);
	errbuf[n] = '\0';
}

/* Fill errbuf with the platform linker's most recent error string. */
static void ck_last_error(char *errbuf, size_t errlen) {
#if defined(_WIN32)
	DWORD code = GetLastError();
	char *msg = NULL;
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
	                   FORMAT_MESSAGE_IGNORE_INSERTS,
	               NULL, code, 0, (char *)&msg, 0, NULL);
	ck_set_err(errbuf, errlen, msg ? msg : "LoadLibrary failed");
	if (msg) {
		LocalFree(msg);
	}
#else
	ck_set_err(errbuf, errlen, dlerror());
#endif
}

/* Close a dynamic-library handle across platforms. */
static void ck_close(void *dl) {
	if (dl == NULL) {
		return;
	}
#if defined(_WIN32)
	FreeLibrary((HMODULE)dl);
#else
	dlclose(dl);
#endif
}

/* Overwrite n bytes at p with zeros, defeating dead-store elimination. Used to
 * scrub secret material (PINs, plaintext, key bytes) before free(). */
void ck_memzero(void *p, size_t n) {
	if (p == NULL || n == 0) {
		return;
	}
#if defined(_WIN32)
	SecureZeroMemory(p, n);
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || \
    (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))) || \
    (defined(__APPLE__) && defined(__MACH__))
	explicit_bzero(p, n);
#else
	volatile unsigned char *v = (volatile unsigned char *)p;
	while (n--) {
		*v++ = 0;
	}
#endif
}

/* REQUIRE_M rejects a NULL module (e.g. a call made after ck_unload zeroed the
 * Go-side handle) instead of dereferencing it. Without this a use-after-Close
 * dereferences m->fns and crashes the process. */
#define REQUIRE_M(m)                                       \
	do {                                                   \
		if ((m) == NULL || (m)->fns == NULL) {             \
			return CKR_CRYPTOKI_NOT_INITIALIZED;            \
		}                                                  \
	} while (0)

/* Try to obtain the 3.2 function list via C_GetInterface("PKCS 11"). Leaves
 * m->fns32 NULL if the module predates 3.0 or does not offer a >= 3.2
 * interface. The default interface name "PKCS 11" is defined by the spec. */
static void ck_resolve_v32(ckModule *m) {
	ck_get_interface_fn get_interface =
	    (ck_get_interface_fn)ck_sym(m->dl, "C_GetInterface");
	if (get_interface == NULL) {
		return;
	}

	CK_INTERFACE_PTR iface = NULL;
	CK_UTF8CHAR name[] = "PKCS 11";
	/* NULL version asks the module for its newest interface. */
	if (get_interface(name, NULL_PTR, &iface, 0) != CKR_OK || iface == NULL) {
		return;
	}

	CK_FUNCTION_LIST_3_2_PTR list = (CK_FUNCTION_LIST_3_2_PTR)iface->pFunctionList;
	if (list == NULL) {
		return;
	}
	if (list->version.major > 3 ||
	    (list->version.major == 3 && list->version.minor >= 2)) {
		m->fns32 = list;
	}
}

ckModule *ck_load(const char *path, CK_RV *rv, char *errbuf, size_t errlen) {
	*rv = CKR_GENERAL_ERROR;

	ckModule *m = (ckModule *)calloc(1, sizeof(*m));
	if (m == NULL) {
		*rv = CKR_HOST_MEMORY;
		ck_set_err(errbuf, errlen, "out of memory");
		return NULL;
	}

#if defined(_WIN32)
	m->dl = (void *)LoadLibraryExA(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
#else
	m->dl = dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
	if (m->dl == NULL) {
		ck_last_error(errbuf, errlen);
		free(m);
		return NULL;
	}

	ck_get_function_list_fn get_list =
	    (ck_get_function_list_fn)ck_sym(m->dl, "C_GetFunctionList");
	if (get_list == NULL) {
		ck_set_err(errbuf, errlen, "module exports no C_GetFunctionList");
		ck_close(m->dl);
		free(m);
		return NULL;
	}

	CK_RV r = get_list(&m->fns);
	if (r != CKR_OK || m->fns == NULL) {
		*rv = (r != CKR_OK) ? r : CKR_GENERAL_ERROR;
		ck_set_err(errbuf, errlen, "C_GetFunctionList failed");
		ck_close(m->dl);
		free(m);
		return NULL;
	}

	ck_resolve_v32(m); /* best effort; m->fns32 stays NULL when unavailable */

	*rv = CKR_OK;
	return m;
}

void ck_unload(ckModule *m) {
	if (m == NULL) {
		return;
	}
	ck_close(m->dl);
	free(m);
}

int ck_has_v32(ckModule *m) {
	return (m != NULL && m->fns32 != NULL) ? 1 : 0;
}

CK_RV ck_initialize(ckModule *m, CK_FLAGS flags, CK_VOID_PTR reserved) {
	REQUIRE_M(m);
	CK_C_INITIALIZE_ARGS args;
	memset(&args, 0, sizeof(args));
	args.flags = flags;
	args.pReserved = reserved;
	return m->fns->C_Initialize(&args);
}

CK_RV ck_finalize(ckModule *m) {
	REQUIRE_M(m);
	return m->fns->C_Finalize(NULL_PTR);
}

CK_RV ck_get_info(ckModule *m, alignedCKInfo *out) {
	REQUIRE_M(m);
	CK_INFO info;
	memset(&info, 0, sizeof(info));
	CK_RV rv = m->fns->C_GetInfo(&info);
	if (rv != CKR_OK) {
		return rv;
	}
	out->cryptokiVersion = info.cryptokiVersion;
	memcpy(out->manufacturerID, info.manufacturerID, sizeof(out->manufacturerID));
	out->flags = info.flags;
	memcpy(out->libraryDescription, info.libraryDescription,
	       sizeof(out->libraryDescription));
	out->libraryVersion = info.libraryVersion;
	return rv;
}

/* ── Slots & tokens ───────────────────────────────────────────────────────── */

CK_RV ck_get_slot_list(ckModule *m, CK_BBOOL tokenPresent, CK_SLOT_ID_PTR list,
                       CK_ULONG_PTR count) {
	REQUIRE_M(m);
	return m->fns->C_GetSlotList(tokenPresent, list, count);
}

CK_RV ck_get_slot_info(ckModule *m, CK_SLOT_ID slot, CK_SLOT_INFO_PTR info) {
	REQUIRE_M(m);
	return m->fns->C_GetSlotInfo(slot, info);
}

CK_RV ck_get_token_info(ckModule *m, CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info) {
	REQUIRE_M(m);
	return m->fns->C_GetTokenInfo(slot, info);
}

CK_RV ck_get_mechanism_list(ckModule *m, CK_SLOT_ID slot,
                            CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count) {
	REQUIRE_M(m);
	return m->fns->C_GetMechanismList(slot, list, count);
}

CK_RV ck_get_mechanism_info(ckModule *m, CK_SLOT_ID slot, CK_MECHANISM_TYPE type,
                            CK_MECHANISM_INFO_PTR info) {
	REQUIRE_M(m);
	return m->fns->C_GetMechanismInfo(slot, type, info);
}

CK_RV ck_init_token(ckModule *m, CK_SLOT_ID slot, CK_UTF8CHAR_PTR pin,
                    CK_ULONG pinLen, CK_UTF8CHAR_PTR label) {
	REQUIRE_M(m);
	return m->fns->C_InitToken(slot, pin, pinLen, label);
}

CK_RV ck_init_pin(ckModule *m, CK_SESSION_HANDLE sh, CK_UTF8CHAR_PTR pin,
                  CK_ULONG pinLen) {
	REQUIRE_M(m);
	return m->fns->C_InitPIN(sh, pin, pinLen);
}

CK_RV ck_set_pin(ckModule *m, CK_SESSION_HANDLE sh, CK_UTF8CHAR_PTR oldPin,
                 CK_ULONG oldLen, CK_UTF8CHAR_PTR newPin, CK_ULONG newLen) {
	REQUIRE_M(m);
	return m->fns->C_SetPIN(sh, oldPin, oldLen, newPin, newLen);
}

/* ── Sessions ─────────────────────────────────────────────────────────────── */

CK_RV ck_open_session(ckModule *m, CK_SLOT_ID slot, CK_FLAGS flags,
                      CK_SESSION_HANDLE_PTR sh) {
	REQUIRE_M(m);
	return m->fns->C_OpenSession(slot, flags, NULL_PTR, NULL_PTR, sh);
}

CK_RV ck_close_session(ckModule *m, CK_SESSION_HANDLE sh) {
	REQUIRE_M(m);
	return m->fns->C_CloseSession(sh);
}

CK_RV ck_close_all_sessions(ckModule *m, CK_SLOT_ID slot) {
	REQUIRE_M(m);
	return m->fns->C_CloseAllSessions(slot);
}

CK_RV ck_get_session_info(ckModule *m, CK_SESSION_HANDLE sh,
                          CK_SESSION_INFO_PTR info) {
	REQUIRE_M(m);
	return m->fns->C_GetSessionInfo(sh, info);
}

CK_RV ck_login(ckModule *m, CK_SESSION_HANDLE sh, CK_USER_TYPE user,
               CK_UTF8CHAR_PTR pin, CK_ULONG pinLen) {
	REQUIRE_M(m);
	return m->fns->C_Login(sh, user, pin, pinLen);
}

CK_RV ck_logout(ckModule *m, CK_SESSION_HANDLE sh) {
	REQUIRE_M(m);
	return m->fns->C_Logout(sh);
}

/* ── Objects & attributes ─────────────────────────────────────────────────── */

CK_RV ck_create_object(ckModule *m, CK_SESSION_HANDLE sh, CK_ATTRIBUTE_PTR tmpl,
                       CK_ULONG n, CK_OBJECT_HANDLE_PTR obj) {
	REQUIRE_M(m);
	return m->fns->C_CreateObject(sh, tmpl, n, obj);
}

CK_RV ck_destroy_object(ckModule *m, CK_SESSION_HANDLE sh, CK_OBJECT_HANDLE obj) {
	REQUIRE_M(m);
	return m->fns->C_DestroyObject(sh, obj);
}

CK_RV ck_get_object_size(ckModule *m, CK_SESSION_HANDLE sh, CK_OBJECT_HANDLE obj,
                         CK_ULONG_PTR size) {
	REQUIRE_M(m);
	return m->fns->C_GetObjectSize(sh, obj, size);
}

CK_RV ck_get_attribute_value(ckModule *m, CK_SESSION_HANDLE sh,
                             CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR tmpl,
                             CK_ULONG n) {
	REQUIRE_M(m);
	return m->fns->C_GetAttributeValue(sh, obj, tmpl, n);
}

CK_RV ck_set_attribute_value(ckModule *m, CK_SESSION_HANDLE sh,
                             CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR tmpl,
                             CK_ULONG n) {
	REQUIRE_M(m);
	return m->fns->C_SetAttributeValue(sh, obj, tmpl, n);
}

CK_RV ck_find_objects_init(ckModule *m, CK_SESSION_HANDLE sh,
                           CK_ATTRIBUTE_PTR tmpl, CK_ULONG n) {
	REQUIRE_M(m);
	return m->fns->C_FindObjectsInit(sh, tmpl, n);
}

CK_RV ck_find_objects(ckModule *m, CK_SESSION_HANDLE sh, CK_OBJECT_HANDLE_PTR objs,
                      CK_ULONG max, CK_ULONG_PTR count) {
	REQUIRE_M(m);
	return m->fns->C_FindObjects(sh, objs, max, count);
}

CK_RV ck_find_objects_final(ckModule *m, CK_SESSION_HANDLE sh) {
	REQUIRE_M(m);
	return m->fns->C_FindObjectsFinal(sh);
}

/* ── Random ───────────────────────────────────────────────────────────────── */

CK_RV ck_seed_random(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR seed,
                     CK_ULONG len) {
	REQUIRE_M(m);
	return m->fns->C_SeedRandom(sh, seed, len);
}

CK_RV ck_generate_random(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR buf,
                         CK_ULONG len) {
	REQUIRE_M(m);
	return m->fns->C_GenerateRandom(sh, buf, len);
}

/* ── Digest ───────────────────────────────────────────────────────────────── */

CK_RV ck_digest_init(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech) {
	REQUIRE_M(m);
	return m->fns->C_DigestInit(sh, mech);
}

CK_RV ck_digest(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_Digest(sh, data, dataLen, out, outLen);
}

CK_RV ck_digest_update(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                       CK_ULONG dataLen) {
	REQUIRE_M(m);
	return m->fns->C_DigestUpdate(sh, data, dataLen);
}

CK_RV ck_digest_key(ckModule *m, CK_SESSION_HANDLE sh, CK_OBJECT_HANDLE key) {
	REQUIRE_M(m);
	return m->fns->C_DigestKey(sh, key);
}

CK_RV ck_digest_final(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR out,
                      CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_DigestFinal(sh, out, outLen);
}

/* ── Encrypt / Decrypt ────────────────────────────────────────────────────── */

CK_RV ck_encrypt_init(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                      CK_OBJECT_HANDLE key) {
	REQUIRE_M(m);
	return m->fns->C_EncryptInit(sh, mech, key);
}

CK_RV ck_encrypt(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                 CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_Encrypt(sh, data, dataLen, out, outLen);
}

CK_RV ck_encrypt_update(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                        CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_EncryptUpdate(sh, data, dataLen, out, outLen);
}

CK_RV ck_encrypt_final(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR out,
                       CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_EncryptFinal(sh, out, outLen);
}

CK_RV ck_decrypt_init(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                      CK_OBJECT_HANDLE key) {
	REQUIRE_M(m);
	return m->fns->C_DecryptInit(sh, mech, key);
}

CK_RV ck_decrypt(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                 CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_Decrypt(sh, data, dataLen, out, outLen);
}

CK_RV ck_decrypt_update(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                        CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_DecryptUpdate(sh, data, dataLen, out, outLen);
}

CK_RV ck_decrypt_final(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR out,
                       CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_DecryptFinal(sh, out, outLen);
}

/* ── Sign / Verify ────────────────────────────────────────────────────────── */

CK_RV ck_sign_init(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                   CK_OBJECT_HANDLE key) {
	REQUIRE_M(m);
	return m->fns->C_SignInit(sh, mech, key);
}

CK_RV ck_sign(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
              CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_Sign(sh, data, dataLen, out, outLen);
}

CK_RV ck_sign_update(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                     CK_ULONG dataLen) {
	REQUIRE_M(m);
	return m->fns->C_SignUpdate(sh, data, dataLen);
}

CK_RV ck_sign_final(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR out,
                    CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_SignFinal(sh, out, outLen);
}

CK_RV ck_verify_init(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                     CK_OBJECT_HANDLE key) {
	REQUIRE_M(m);
	return m->fns->C_VerifyInit(sh, mech, key);
}

CK_RV ck_verify(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                CK_ULONG dataLen, CK_BYTE_PTR sig, CK_ULONG sigLen) {
	REQUIRE_M(m);
	return m->fns->C_Verify(sh, data, dataLen, sig, sigLen);
}

CK_RV ck_verify_update(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                       CK_ULONG dataLen) {
	REQUIRE_M(m);
	return m->fns->C_VerifyUpdate(sh, data, dataLen);
}

CK_RV ck_verify_final(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR sig,
                      CK_ULONG sigLen) {
	REQUIRE_M(m);
	return m->fns->C_VerifyFinal(sh, sig, sigLen);
}

/* ── Key generation ───────────────────────────────────────────────────────── */

CK_RV ck_generate_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                      CK_ATTRIBUTE_PTR tmpl, CK_ULONG n, CK_OBJECT_HANDLE_PTR key) {
	REQUIRE_M(m);
	return m->fns->C_GenerateKey(sh, mech, tmpl, n, key);
}

CK_RV ck_generate_key_pair(ckModule *m, CK_SESSION_HANDLE sh,
                           CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR pub,
                           CK_ULONG nPub, CK_ATTRIBUTE_PTR priv, CK_ULONG nPriv,
                           CK_OBJECT_HANDLE_PTR hPub, CK_OBJECT_HANDLE_PTR hPriv) {
	REQUIRE_M(m);
	return m->fns->C_GenerateKeyPair(sh, mech, pub, nPub, priv, nPriv, hPub, hPriv);
}

/* ── Wrap / Unwrap / Derive (v2.x) ────────────────────────────────────────── */

CK_RV ck_wrap_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                  CK_OBJECT_HANDLE wrappingKey, CK_OBJECT_HANDLE key,
                  CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_WrapKey(sh, mech, wrappingKey, key, out, outLen);
}

CK_RV ck_unwrap_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                    CK_OBJECT_HANDLE unwrappingKey, CK_BYTE_PTR wrapped,
                    CK_ULONG wrappedLen, CK_ATTRIBUTE_PTR tmpl, CK_ULONG n,
                    CK_OBJECT_HANDLE_PTR key) {
	REQUIRE_M(m);
	return m->fns->C_UnwrapKey(sh, mech, unwrappingKey, wrapped, wrappedLen, tmpl, n, key);
}

CK_RV ck_derive_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                    CK_OBJECT_HANDLE baseKey, CK_ATTRIBUTE_PTR tmpl, CK_ULONG n,
                    CK_OBJECT_HANDLE_PTR key) {
	REQUIRE_M(m);
	return m->fns->C_DeriveKey(sh, mech, baseKey, tmpl, n, key);
}

/* ── Object copy ──────────────────────────────────────────────────────────── */

CK_RV ck_copy_object(ckModule *m, CK_SESSION_HANDLE sh, CK_OBJECT_HANDLE obj,
                     CK_ATTRIBUTE_PTR tmpl, CK_ULONG n,
                     CK_OBJECT_HANDLE_PTR newObj) {
	REQUIRE_M(m);
	return m->fns->C_CopyObject(sh, obj, tmpl, n, newObj);
}

/* ── Operation state ──────────────────────────────────────────────────────── */

CK_RV ck_get_operation_state(ckModule *m, CK_SESSION_HANDLE sh,
                             CK_BYTE_PTR state, CK_ULONG_PTR stateLen) {
	REQUIRE_M(m);
	return m->fns->C_GetOperationState(sh, state, stateLen);
}

CK_RV ck_set_operation_state(ckModule *m, CK_SESSION_HANDLE sh,
                             CK_BYTE_PTR state, CK_ULONG stateLen,
                             CK_OBJECT_HANDLE encKey, CK_OBJECT_HANDLE authKey) {
	REQUIRE_M(m);
	return m->fns->C_SetOperationState(sh, state, stateLen, encKey, authKey);
}

/* ── Slot events ──────────────────────────────────────────────────────────── */

CK_RV ck_wait_for_slot_event(ckModule *m, CK_FLAGS flags, CK_SLOT_ID_PTR slot) {
	REQUIRE_M(m);
	return m->fns->C_WaitForSlotEvent(flags, slot, NULL_PTR);
}

/* ── Combined digest+encrypt / decrypt+digest / sign+encrypt streaming ───── */

CK_RV ck_digest_encrypt_update(ckModule *m, CK_SESSION_HANDLE sh,
                               CK_BYTE_PTR part, CK_ULONG partLen,
                               CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_DigestEncryptUpdate(sh, part, partLen, out, outLen);
}

CK_RV ck_decrypt_digest_update(ckModule *m, CK_SESSION_HANDLE sh,
                               CK_BYTE_PTR cipher, CK_ULONG cipherLen,
                               CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_DecryptDigestUpdate(sh, cipher, cipherLen, out, outLen);
}

CK_RV ck_sign_encrypt_update(ckModule *m, CK_SESSION_HANDLE sh,
                             CK_BYTE_PTR part, CK_ULONG partLen,
                             CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_SignEncryptUpdate(sh, part, partLen, out, outLen);
}

CK_RV ck_decrypt_verify_update(ckModule *m, CK_SESSION_HANDLE sh,
                               CK_BYTE_PTR cipher, CK_ULONG cipherLen,
                               CK_BYTE_PTR out, CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	return m->fns->C_DecryptVerifyUpdate(sh, cipher, cipherLen, out, outLen);
}

/* ── PKCS #11 v3.2 entry points (dispatched via the 3.2 function list) ─────── */

/* Guard: a v3.2-only call on a module that exposed only a 2.x interface. */
#define REQUIRE_V32(m)                            \
	do {                                          \
		if ((m)->fns32 == NULL) {                 \
			return CKR_FUNCTION_NOT_SUPPORTED;    \
		}                                         \
	} while (0)

CK_RV ck_encapsulate_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                         CK_OBJECT_HANDLE pubKey, CK_ATTRIBUTE_PTR tmpl,
                         CK_ULONG n, CK_BYTE_PTR ct, CK_ULONG_PTR ctLen,
                         CK_OBJECT_HANDLE_PTR key) {
	REQUIRE_M(m);
	REQUIRE_V32(m);
	return m->fns32->C_EncapsulateKey(sh, mech, pubKey, tmpl, n, ct, ctLen, key);
}

CK_RV ck_decapsulate_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                         CK_OBJECT_HANDLE privKey, CK_ATTRIBUTE_PTR tmpl,
                         CK_ULONG n, CK_BYTE_PTR ct, CK_ULONG ctLen,
                         CK_OBJECT_HANDLE_PTR key) {
	REQUIRE_M(m);
	REQUIRE_V32(m);
	return m->fns32->C_DecapsulateKey(sh, mech, privKey, tmpl, n, ct, ctLen, key);
}

CK_RV ck_verify_signature_init(ckModule *m, CK_SESSION_HANDLE sh,
                               CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key,
                               CK_BYTE_PTR sig, CK_ULONG sigLen) {
	REQUIRE_M(m);
	REQUIRE_V32(m);
	return m->fns32->C_VerifySignatureInit(sh, mech, key, sig, sigLen);
}

CK_RV ck_verify_signature(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                          CK_ULONG dataLen) {
	REQUIRE_M(m);
	REQUIRE_V32(m);
	return m->fns32->C_VerifySignature(sh, data, dataLen);
}

CK_RV ck_verify_signature_update(ckModule *m, CK_SESSION_HANDLE sh,
                                 CK_BYTE_PTR part, CK_ULONG partLen) {
	REQUIRE_M(m);
	REQUIRE_V32(m);
	return m->fns32->C_VerifySignatureUpdate(sh, part, partLen);
}

CK_RV ck_verify_signature_final(ckModule *m, CK_SESSION_HANDLE sh) {
	REQUIRE_M(m);
	REQUIRE_V32(m);
	return m->fns32->C_VerifySignatureFinal(sh);
}

CK_RV ck_get_session_validation_flags(ckModule *m, CK_SESSION_HANDLE sh,
                                      CK_SESSION_VALIDATION_FLAGS_TYPE type,
                                      CK_FLAGS_PTR flags) {
	REQUIRE_M(m);
	REQUIRE_V32(m);
	return m->fns32->C_GetSessionValidationFlags(sh, type, flags);
}

CK_RV ck_wrap_key_authenticated(ckModule *m, CK_SESSION_HANDLE sh,
                                CK_MECHANISM_PTR mech,
                                CK_OBJECT_HANDLE wrappingKey,
                                CK_OBJECT_HANDLE key, CK_BYTE_PTR aad,
                                CK_ULONG aadLen, CK_BYTE_PTR out,
                                CK_ULONG_PTR outLen) {
	REQUIRE_M(m);
	REQUIRE_V32(m);
	return m->fns32->C_WrapKeyAuthenticated(sh, mech, wrappingKey, key, aad,
	                                        aadLen, out, outLen);
}

CK_RV ck_unwrap_key_authenticated(ckModule *m, CK_SESSION_HANDLE sh,
                                  CK_MECHANISM_PTR mech,
                                  CK_OBJECT_HANDLE unwrappingKey,
                                  CK_BYTE_PTR wrapped, CK_ULONG wrappedLen,
                                  CK_ATTRIBUTE_PTR tmpl, CK_ULONG n,
                                  CK_BYTE_PTR aad, CK_ULONG aadLen,
                                  CK_OBJECT_HANDLE_PTR key) {
	REQUIRE_M(m);
	REQUIRE_V32(m);
	return m->fns32->C_UnwrapKeyAuthenticated(sh, mech, unwrappingKey, wrapped,
	                                          wrappedLen, tmpl, n, aad, aadLen, key);
}
