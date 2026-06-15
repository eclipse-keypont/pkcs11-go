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
	"unsafe"
)

// NewAttribute builds an Attribute for a CKA_ type, encoding value into the raw
// bytes Cryptoki expects:
//
//	nil            → no value (length query / absent)
//	bool           → CK_BBOOL (1 byte)
//	int, uint      → CK_ULONG in the platform's native width
//	string, []byte → the bytes as-is (copied, so later mutation/wipe is safe)
//
// It panics on an unsupported value type, a negative int, or a value that does
// not fit the platform's CK_ULONG, mirroring how a misuse here is a programming
// error rather than a runtime condition.
func NewAttribute(typ uint, value any) *Attribute {
	a := &Attribute{Type: typ}
	switch v := value.(type) {
	case nil:
		// leave Value nil
	case bool:
		a.Value = ckBBool(v)
	case int:
		if v < 0 {
			panic("cryptoki: NewAttribute: negative int is not a valid CK_ULONG")
		}
		a.Value = ckULong(uint(v))
	case uint:
		a.Value = ckULong(v)
	case string:
		a.Value = []byte(v)
	case []byte:
		// Copy so the attribute does not alias (and is not corrupted by a later
		// wipe of) the caller's slice.
		a.Value = append([]byte(nil), v...)
	default:
		panic(fmt.Sprintf("cryptoki: NewAttribute: unsupported value type %T", value))
	}
	return a
}

// CopyObject creates a copy of an object on the same session, applying an
// optional template to override or add attributes in the copy (C_CopyObject).
func (c *Ctx) CopyObject(sh SessionHandle, obj ObjectHandle, tmpl []*Attribute) (ObjectHandle, error) {
	m, release, err := c.grab()
	if err != nil {
		return 0, err
	}
	defer release()
	arr, n, freeAttrs := cAttributes(tmpl)
	defer freeAttrs()

	var newObj C.CK_OBJECT_HANDLE
	rv := C.ck_copy_object(m, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(obj), arr, n, &newObj)
	if err := toError(uint(rv)); err != nil {
		return 0, err
	}
	return ObjectHandle(newObj), nil
}

// CreateObject creates a new object from a template (C_CreateObject).
func (c *Ctx) CreateObject(sh SessionHandle, tmpl []*Attribute) (ObjectHandle, error) {
	m, release, err := c.grab()
	if err != nil {
		return 0, err
	}
	defer release()
	arr, n, freeAttrs := cAttributes(tmpl)
	defer freeAttrs()

	var obj C.CK_OBJECT_HANDLE
	rv := C.ck_create_object(m, C.CK_SESSION_HANDLE(sh), arr, n, &obj)
	if err := toError(uint(rv)); err != nil {
		return 0, err
	}
	return ObjectHandle(obj), nil
}

// DestroyObject destroys an object (C_DestroyObject).
func (c *Ctx) DestroyObject(sh SessionHandle, obj ObjectHandle) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	rv := C.ck_destroy_object(m, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(obj))
	return toError(uint(rv))
}

// GetObjectSize returns the size of an object in bytes (C_GetObjectSize).
func (c *Ctx) GetObjectSize(sh SessionHandle, obj ObjectHandle) (uint, error) {
	m, release, err := c.grab()
	if err != nil {
		return 0, err
	}
	defer release()
	var size C.CK_ULONG
	rv := C.ck_get_object_size(m, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(obj), &size)
	if err := toError(uint(rv)); err != nil {
		return 0, err
	}
	return uint(size), nil
}

// GetAttributeValue reads attribute values for an object (C_GetAttributeValue).
// Pass a template of Attributes with nil Value naming the types to read; the
// returned slice has the same length and order, with values filled in.
// Attributes the token reports as unavailable — including ones it refuses
// because they are sensitive — come back with a nil Value.
//
// When some requested attributes are sensitive or type-invalid, Cryptoki still
// fills in the readable ones and returns CKR_ATTRIBUTE_SENSITIVE or
// CKR_ATTRIBUTE_TYPE_INVALID. In that case GetAttributeValue returns the
// (partially populated) slice together with that error, so a caller can tell
// "sensitive/absent" apart from a hard failure. Value buffers are scrubbed
// before being freed, since they may hold key material.
func (c *Ctx) GetAttributeValue(sh SessionHandle, obj ObjectHandle, tmpl []*Attribute) ([]*Attribute, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()

	n := len(tmpl)
	if n == 0 {
		return nil, nil
	}
	arr := (*C.CK_ATTRIBUTE)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.CK_ATTRIBUTE{}))))
	defer C.free(unsafe.Pointer(arr))
	list := unsafe.Slice(arr, n)
	for i, a := range tmpl {
		list[i]._type = C.CK_ATTRIBUTE_TYPE(a.Type)
		list[i].pValue = nil
		list[i].ulValueLen = 0
	}

	// partialOK reports whether rv is a "soft" failure: the call still filled in
	// the lengths of the attributes it could read.
	partialOK := func(rv uint) bool {
		return rv == CKR_OK ||
			rv == CKR_ATTRIBUTE_SENSITIVE ||
			rv == CKR_ATTRIBUTE_TYPE_INVALID
	}

	// First pass: learn each readable value's length.
	rv := uint(C.ck_get_attribute_value(m, C.CK_SESSION_HANDLE(sh),
		C.CK_OBJECT_HANDLE(obj), arr, C.CK_ULONG(n)))
	if !partialOK(rv) {
		return nil, toError(rv)
	}

	unavailable := C.CK_ULONG(C.CK_UNAVAILABLE_INFORMATION)
	for i := range list {
		if list[i].ulValueLen != unavailable && list[i].ulValueLen > 0 {
			list[i].pValue = C.CK_VOID_PTR(C.malloc(C.size_t(list[i].ulValueLen)))
		}
	}
	defer func() {
		for i := range list {
			if list[i].pValue != nil {
				zfree(unsafe.Pointer(list[i].pValue), C.CK_ULONG(list[i].ulValueLen))
			}
		}
	}()

	// Second pass: read the values into the allocated buffers. Re-check for the
	// soft codes (they can also surface here).
	rv = uint(C.ck_get_attribute_value(m, C.CK_SESSION_HANDLE(sh),
		C.CK_OBJECT_HANDLE(obj), arr, C.CK_ULONG(n)))
	if !partialOK(rv) {
		return nil, toError(rv)
	}

	out := make([]*Attribute, n)
	for i := range list {
		a := &Attribute{Type: uint(list[i]._type)}
		if list[i].pValue != nil && list[i].ulValueLen != unavailable && list[i].ulValueLen > 0 {
			a.Value = C.GoBytes(unsafe.Pointer(list[i].pValue), C.int(list[i].ulValueLen))
		}
		out[i] = a
	}
	// Surface the soft failure (if any) alongside the partial results.
	return out, toError(rv)
}

// SetAttributeValue modifies attribute values on an object (C_SetAttributeValue).
func (c *Ctx) SetAttributeValue(sh SessionHandle, obj ObjectHandle, tmpl []*Attribute) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	arr, n, freeAttrs := cAttributes(tmpl)
	defer freeAttrs()
	rv := C.ck_set_attribute_value(m, C.CK_SESSION_HANDLE(sh), C.CK_OBJECT_HANDLE(obj), arr, n)
	return toError(uint(rv))
}

// FindObjectsInit begins a search for objects matching a template
// (C_FindObjectsInit). An empty template matches all objects.
func (c *Ctx) FindObjectsInit(sh SessionHandle, tmpl []*Attribute) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	arr, n, freeAttrs := cAttributes(tmpl)
	defer freeAttrs()
	return toError(uint(C.ck_find_objects_init(m, C.CK_SESSION_HANDLE(sh), arr, n)))
}

// FindObjects returns up to max object handles from the active search
// (C_FindObjects). A returned slice shorter than max means the search is
// exhausted. Call FindObjectsFinal when done.
func (c *Ctx) FindObjects(sh SessionHandle, max int) ([]ObjectHandle, error) {
	if max <= 0 {
		return nil, nil
	}
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()
	buf := make([]C.CK_OBJECT_HANDLE, max)
	var count C.CK_ULONG
	rv := C.ck_find_objects(m, C.CK_SESSION_HANDLE(sh), &buf[0], C.CK_ULONG(max), &count)
	if err := toError(uint(rv)); err != nil {
		return nil, err
	}
	out := make([]ObjectHandle, count)
	for i := range out {
		out[i] = ObjectHandle(buf[i])
	}
	return out, nil
}

// FindObjectsFinal ends an object search (C_FindObjectsFinal).
func (c *Ctx) FindObjectsFinal(sh SessionHandle) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	return toError(uint(C.ck_find_objects_final(m, C.CK_SESSION_HANDLE(sh))))
}
