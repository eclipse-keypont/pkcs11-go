/*
 * shim.h — C surface the Go binding calls into.
 *
 * SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
 * SPDX-License-Identifier: MIT
 *
 * These wrappers hide two things from Go: the platform-specific dynamic loader
 * (dlopen/LoadLibrary) and the dispatch through a module's CK_FUNCTION_LIST.
 * Each call is forwarded to the resolved function pointer for one loaded
 * module. Declarations only; see shim.c for the implementations.
 */

#ifndef ECLIPSE_KEYPONT_PKCS11_SHIM_H
#define ECLIPSE_KEYPONT_PKCS11_SHIM_H 1

#include <stddef.h>   /* size_t */

#include "platform.h" /* OASIS PKCS #11 headers via the configuration shim */

/*
 * ckModule bundles everything resolved for one loaded PKCS #11 module: the
 * dynamic-library handle, the base (2.x) function list that every module
 * exports, and — when the module advertises PKCS #11 >= 3.2 via C_GetInterface
 * — the richer 3.2 function list used for the v3.2-only entry points.
 */
typedef struct ckModule ckModule;

/*
 * ck_load opens the module shared object at path and resolves its function
 * list(s). On success it returns a non-NULL handle and writes CKR_OK to *rv.
 * On failure it returns NULL and writes the offending CK_RV to *rv, or
 * CKR_GENERAL_ERROR if the failure was in the loader itself (e.g. the file
 * could not be opened or exported no C_GetFunctionList). When the failure is
 * in the loader, a human-readable reason from the platform linker is copied
 * into errbuf (NUL-terminated, truncated to errlen).
 */
ckModule *ck_load(const char *path, CK_RV *rv, char *errbuf, size_t errlen);

/* ck_unload drops the function-list references and closes the library. */
void ck_unload(ckModule *m);

/* ck_memzero overwrites n bytes at p with zeros using a primitive the compiler
 * is not allowed to optimise away (explicit_bzero / SecureZeroMemory / a
 * volatile fallback). Use it before freeing any buffer that held secret
 * material (PINs, plaintext, key bytes). Safe with p == NULL or n == 0. */
void ck_memzero(void *p, size_t n);

/* ck_has_v32 reports whether the 3.2 function list was resolved (1) or not (0). */
int ck_has_v32(ckModule *m);

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

/* ck_initialize calls C_Initialize with a CK_C_INITIALIZE_ARGS built from
 * flags (typically CKF_OS_LOCKING_OK) and the given reserved pointer. */
CK_RV ck_initialize(ckModule *m, CK_FLAGS flags, CK_VOID_PTR reserved);

/* ck_finalize calls C_Finalize(NULL_PTR). */
CK_RV ck_finalize(ckModule *m);

/* ck_get_info calls C_GetInfo and copies the result into a naturally aligned
 * mirror so Go can read it even when CK_INFO is byte-packed. */
CK_RV ck_get_info(ckModule *m, alignedCKInfo *out);

/* ── Slots & tokens ───────────────────────────────────────────────────────── */

CK_RV ck_get_slot_list(ckModule *m, CK_BBOOL tokenPresent,
                       CK_SLOT_ID_PTR list, CK_ULONG_PTR count);
CK_RV ck_get_slot_info(ckModule *m, CK_SLOT_ID slot, CK_SLOT_INFO_PTR info);
CK_RV ck_get_token_info(ckModule *m, CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info);
CK_RV ck_get_mechanism_list(ckModule *m, CK_SLOT_ID slot,
                            CK_MECHANISM_TYPE_PTR list, CK_ULONG_PTR count);
CK_RV ck_get_mechanism_info(ckModule *m, CK_SLOT_ID slot, CK_MECHANISM_TYPE type,
                            CK_MECHANISM_INFO_PTR info);
CK_RV ck_init_token(ckModule *m, CK_SLOT_ID slot, CK_UTF8CHAR_PTR pin,
                    CK_ULONG pinLen, CK_UTF8CHAR_PTR label);
CK_RV ck_init_pin(ckModule *m, CK_SESSION_HANDLE sh, CK_UTF8CHAR_PTR pin,
                  CK_ULONG pinLen);
CK_RV ck_set_pin(ckModule *m, CK_SESSION_HANDLE sh, CK_UTF8CHAR_PTR oldPin,
                 CK_ULONG oldLen, CK_UTF8CHAR_PTR newPin, CK_ULONG newLen);

/* ── Sessions ─────────────────────────────────────────────────────────────── */

CK_RV ck_open_session(ckModule *m, CK_SLOT_ID slot, CK_FLAGS flags,
                      CK_SESSION_HANDLE_PTR sh);
CK_RV ck_close_session(ckModule *m, CK_SESSION_HANDLE sh);
CK_RV ck_close_all_sessions(ckModule *m, CK_SLOT_ID slot);
CK_RV ck_get_session_info(ckModule *m, CK_SESSION_HANDLE sh,
                          CK_SESSION_INFO_PTR info);
CK_RV ck_login(ckModule *m, CK_SESSION_HANDLE sh, CK_USER_TYPE user,
               CK_UTF8CHAR_PTR pin, CK_ULONG pinLen);
CK_RV ck_logout(ckModule *m, CK_SESSION_HANDLE sh);

/* ── Objects & attributes ─────────────────────────────────────────────────── */

CK_RV ck_create_object(ckModule *m, CK_SESSION_HANDLE sh, CK_ATTRIBUTE_PTR tmpl,
                       CK_ULONG n, CK_OBJECT_HANDLE_PTR obj);
CK_RV ck_destroy_object(ckModule *m, CK_SESSION_HANDLE sh, CK_OBJECT_HANDLE obj);
CK_RV ck_get_object_size(ckModule *m, CK_SESSION_HANDLE sh, CK_OBJECT_HANDLE obj,
                         CK_ULONG_PTR size);
CK_RV ck_get_attribute_value(ckModule *m, CK_SESSION_HANDLE sh,
                             CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR tmpl,
                             CK_ULONG n);
CK_RV ck_set_attribute_value(ckModule *m, CK_SESSION_HANDLE sh,
                             CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_PTR tmpl,
                             CK_ULONG n);
CK_RV ck_find_objects_init(ckModule *m, CK_SESSION_HANDLE sh,
                           CK_ATTRIBUTE_PTR tmpl, CK_ULONG n);
CK_RV ck_find_objects(ckModule *m, CK_SESSION_HANDLE sh, CK_OBJECT_HANDLE_PTR objs,
                      CK_ULONG max, CK_ULONG_PTR count);
CK_RV ck_find_objects_final(ckModule *m, CK_SESSION_HANDLE sh);

/* ── Random ───────────────────────────────────────────────────────────────── */

CK_RV ck_seed_random(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR seed,
                     CK_ULONG len);
CK_RV ck_generate_random(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR buf,
                         CK_ULONG len);

/* ── Digest ───────────────────────────────────────────────────────────────── */

CK_RV ck_digest_init(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech);
CK_RV ck_digest(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen);
CK_RV ck_digest_update(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                       CK_ULONG dataLen);
CK_RV ck_digest_key(ckModule *m, CK_SESSION_HANDLE sh, CK_OBJECT_HANDLE key);
CK_RV ck_digest_final(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR out,
                      CK_ULONG_PTR outLen);

/* ── Encrypt / Decrypt ────────────────────────────────────────────────────── */

CK_RV ck_encrypt_init(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                      CK_OBJECT_HANDLE key);
CK_RV ck_encrypt(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                 CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen);
CK_RV ck_encrypt_update(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                        CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen);
CK_RV ck_encrypt_final(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR out,
                       CK_ULONG_PTR outLen);
CK_RV ck_decrypt_init(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                      CK_OBJECT_HANDLE key);
CK_RV ck_decrypt(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                 CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen);
CK_RV ck_decrypt_update(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                        CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen);
CK_RV ck_decrypt_final(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR out,
                       CK_ULONG_PTR outLen);

/* ── Sign / Verify ────────────────────────────────────────────────────────── */

CK_RV ck_sign_init(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                   CK_OBJECT_HANDLE key);
CK_RV ck_sign(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
              CK_ULONG dataLen, CK_BYTE_PTR out, CK_ULONG_PTR outLen);
CK_RV ck_sign_update(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                     CK_ULONG dataLen);
CK_RV ck_sign_final(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR out,
                    CK_ULONG_PTR outLen);
CK_RV ck_verify_init(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                     CK_OBJECT_HANDLE key);
CK_RV ck_verify(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                CK_ULONG dataLen, CK_BYTE_PTR sig, CK_ULONG sigLen);
CK_RV ck_verify_update(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                       CK_ULONG dataLen);
CK_RV ck_verify_final(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR sig,
                      CK_ULONG sigLen);

/* ── Key generation ───────────────────────────────────────────────────────── */

CK_RV ck_generate_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                      CK_ATTRIBUTE_PTR tmpl, CK_ULONG n, CK_OBJECT_HANDLE_PTR key);
CK_RV ck_generate_key_pair(ckModule *m, CK_SESSION_HANDLE sh,
                           CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR pub,
                           CK_ULONG nPub, CK_ATTRIBUTE_PTR priv, CK_ULONG nPriv,
                           CK_OBJECT_HANDLE_PTR hPub, CK_OBJECT_HANDLE_PTR hPriv);

/* ── Wrap / Unwrap / Derive (v2.x) ────────────────────────────────────────── */

CK_RV ck_wrap_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                  CK_OBJECT_HANDLE wrappingKey, CK_OBJECT_HANDLE key,
                  CK_BYTE_PTR out, CK_ULONG_PTR outLen);
CK_RV ck_unwrap_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                    CK_OBJECT_HANDLE unwrappingKey, CK_BYTE_PTR wrapped,
                    CK_ULONG wrappedLen, CK_ATTRIBUTE_PTR tmpl, CK_ULONG n,
                    CK_OBJECT_HANDLE_PTR key);
CK_RV ck_derive_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                    CK_OBJECT_HANDLE baseKey, CK_ATTRIBUTE_PTR tmpl, CK_ULONG n,
                    CK_OBJECT_HANDLE_PTR key);

/* ── Object copy ──────────────────────────────────────────────────────────── */

CK_RV ck_copy_object(ckModule *m, CK_SESSION_HANDLE sh, CK_OBJECT_HANDLE obj,
                     CK_ATTRIBUTE_PTR tmpl, CK_ULONG n,
                     CK_OBJECT_HANDLE_PTR newObj);

/* ── Operation state ──────────────────────────────────────────────────────── */

CK_RV ck_get_operation_state(ckModule *m, CK_SESSION_HANDLE sh,
                             CK_BYTE_PTR state, CK_ULONG_PTR stateLen);
CK_RV ck_set_operation_state(ckModule *m, CK_SESSION_HANDLE sh,
                             CK_BYTE_PTR state, CK_ULONG stateLen,
                             CK_OBJECT_HANDLE encKey, CK_OBJECT_HANDLE authKey);

/* ── Slot events ──────────────────────────────────────────────────────────── */

/* ck_wait_for_slot_event calls C_WaitForSlotEvent(flags, slot, NULL_PTR).
 * Pass CKF_DONT_BLOCK (1) to return immediately with CKR_NO_EVENT when no
 * slot event is pending. */
CK_RV ck_wait_for_slot_event(ckModule *m, CK_FLAGS flags, CK_SLOT_ID_PTR slot);

/* ── Combined digest+encrypt / decrypt+digest / sign+encrypt streaming ───── */

CK_RV ck_digest_encrypt_update(ckModule *m, CK_SESSION_HANDLE sh,
                               CK_BYTE_PTR part, CK_ULONG partLen,
                               CK_BYTE_PTR out, CK_ULONG_PTR outLen);
CK_RV ck_decrypt_digest_update(ckModule *m, CK_SESSION_HANDLE sh,
                               CK_BYTE_PTR cipher, CK_ULONG cipherLen,
                               CK_BYTE_PTR out, CK_ULONG_PTR outLen);
CK_RV ck_sign_encrypt_update(ckModule *m, CK_SESSION_HANDLE sh,
                             CK_BYTE_PTR part, CK_ULONG partLen,
                             CK_BYTE_PTR out, CK_ULONG_PTR outLen);
CK_RV ck_decrypt_verify_update(ckModule *m, CK_SESSION_HANDLE sh,
                               CK_BYTE_PTR cipher, CK_ULONG cipherLen,
                               CK_BYTE_PTR out, CK_ULONG_PTR outLen);

/* ── PKCS #11 v3.2 entry points (dispatched via the 3.2 function list) ─────── */

/* Each of these returns CKR_FUNCTION_NOT_SUPPORTED when the module did not
 * advertise a >= 3.2 interface (i.e. ck_has_v32 is false). */

CK_RV ck_encapsulate_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                         CK_OBJECT_HANDLE pubKey, CK_ATTRIBUTE_PTR tmpl,
                         CK_ULONG n, CK_BYTE_PTR ct, CK_ULONG_PTR ctLen,
                         CK_OBJECT_HANDLE_PTR key);
CK_RV ck_decapsulate_key(ckModule *m, CK_SESSION_HANDLE sh, CK_MECHANISM_PTR mech,
                         CK_OBJECT_HANDLE privKey, CK_ATTRIBUTE_PTR tmpl,
                         CK_ULONG n, CK_BYTE_PTR ct, CK_ULONG ctLen,
                         CK_OBJECT_HANDLE_PTR key);

CK_RV ck_verify_signature_init(ckModule *m, CK_SESSION_HANDLE sh,
                               CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key,
                               CK_BYTE_PTR sig, CK_ULONG sigLen);
CK_RV ck_verify_signature(ckModule *m, CK_SESSION_HANDLE sh, CK_BYTE_PTR data,
                          CK_ULONG dataLen);
CK_RV ck_verify_signature_update(ckModule *m, CK_SESSION_HANDLE sh,
                                 CK_BYTE_PTR part, CK_ULONG partLen);
CK_RV ck_verify_signature_final(ckModule *m, CK_SESSION_HANDLE sh);

CK_RV ck_get_session_validation_flags(ckModule *m, CK_SESSION_HANDLE sh,
                                      CK_SESSION_VALIDATION_FLAGS_TYPE type,
                                      CK_FLAGS_PTR flags);

CK_RV ck_wrap_key_authenticated(ckModule *m, CK_SESSION_HANDLE sh,
                                CK_MECHANISM_PTR mech,
                                CK_OBJECT_HANDLE wrappingKey,
                                CK_OBJECT_HANDLE key, CK_BYTE_PTR aad,
                                CK_ULONG aadLen, CK_BYTE_PTR out,
                                CK_ULONG_PTR outLen);
CK_RV ck_unwrap_key_authenticated(ckModule *m, CK_SESSION_HANDLE sh,
                                  CK_MECHANISM_PTR mech,
                                  CK_OBJECT_HANDLE unwrappingKey,
                                  CK_BYTE_PTR wrapped, CK_ULONG wrappedLen,
                                  CK_ATTRIBUTE_PTR tmpl, CK_ULONG n,
                                  CK_BYTE_PTR aad, CK_ULONG aadLen,
                                  CK_OBJECT_HANDLE_PTR key);

#endif /* ECLIPSE_KEYPONT_PKCS11_SHIM_H */
