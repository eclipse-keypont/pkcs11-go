// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package p11

import (
	"fmt"

	"github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// Object is a handle to an object on a token, bound to the session it was found
// or created in.
type Object struct {
	session *Session
	handle  cryptoki.ObjectHandle
}

// Handle returns the underlying cryptoki object handle.
func (o Object) Handle() cryptoki.ObjectHandle { return o.handle }

// Attribute reads the raw bytes of a single attribute (C_GetAttributeValue).
// It errors if the token reports the attribute as unavailable or sensitive.
func (o Object) Attribute(attributeType uint) ([]byte, error) {
	o.session.mu.Lock()
	defer o.session.mu.Unlock()
	attrs, err := o.session.ctx.GetAttributeValue(o.session.handle, o.handle,
		[]*cryptoki.Attribute{cryptoki.NewAttribute(attributeType, nil)})
	if err != nil {
		return nil, err
	}
	if len(attrs) == 0 || attrs[0].Value == nil {
		return nil, fmt.Errorf("p11: attribute %#x unavailable", attributeType)
	}
	return attrs[0].Value, nil
}

// Attributes reads several attributes at once, returning them in request order.
// If some are sensitive or type-invalid the readable ones are still returned,
// together with the underlying error, so callers can distinguish the cases.
func (o Object) Attributes(attributeTypes ...uint) ([]*cryptoki.Attribute, error) {
	tmpl := make([]*cryptoki.Attribute, len(attributeTypes))
	for i, t := range attributeTypes {
		tmpl[i] = cryptoki.NewAttribute(t, nil)
	}
	o.session.mu.Lock()
	defer o.session.mu.Unlock()
	return o.session.ctx.GetAttributeValue(o.session.handle, o.handle, tmpl)
}

// Label returns the object's CKA_LABEL as a string.
func (o Object) Label() (string, error) {
	v, err := o.Attribute(cryptoki.CKA_LABEL)
	if err != nil {
		return "", err
	}
	return string(v), nil
}

// Value returns the object's CKA_VALUE bytes (only for objects that expose it).
func (o Object) Value() ([]byte, error) {
	return o.Attribute(cryptoki.CKA_VALUE)
}

// SetAttribute sets one attribute value (C_SetAttributeValue).
func (o Object) SetAttribute(attributeType uint, value []byte) error {
	o.session.mu.Lock()
	defer o.session.mu.Unlock()
	return o.session.ctx.SetAttributeValue(o.session.handle, o.handle,
		[]*cryptoki.Attribute{{Type: attributeType, Value: value}})
}

// Copy creates a copy of the object in the same session, applying optional
// attribute overrides (C_CopyObject). Use it to, for example, convert a
// session object to a token object or change its label.
func (o Object) Copy(tmpl []*cryptoki.Attribute) (Object, error) {
	o.session.mu.Lock()
	defer o.session.mu.Unlock()
	h, err := o.session.ctx.CopyObject(o.session.handle, o.handle, tmpl)
	if err != nil {
		return Object{}, err
	}
	return Object{session: o.session, handle: h}, nil
}

// Destroy removes the object from the token (C_DestroyObject).
func (o Object) Destroy() error {
	o.session.mu.Lock()
	defer o.session.mu.Unlock()
	return o.session.ctx.DestroyObject(o.session.handle, o.handle)
}
