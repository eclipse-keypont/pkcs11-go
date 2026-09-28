// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package p11

import (
	"testing"

	"github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// TestWithSecureDefaultsAddsMissing checks that the secure attributes are added
// when the caller does not set them.
func TestWithSecureDefaultsAddsMissing(t *testing.T) {
	tmpl := []*cryptoki.Attribute{
		cryptoki.NewAttribute(cryptoki.CKA_CLASS, uint(cryptoki.CKO_SECRET_KEY)),
	}
	out := withSecureDefaults(tmpl, true)

	if !hasAttribute(out, cryptoki.CKA_SENSITIVE) {
		t.Error("CKA_SENSITIVE not added")
	}
	if !hasAttribute(out, cryptoki.CKA_EXTRACTABLE) {
		t.Error("CKA_EXTRACTABLE not added")
	}
	if !hasAttribute(out, cryptoki.CKA_PRIVATE) {
		t.Error("CKA_PRIVATE not added for private object")
	}
	// The caller's slice must not be mutated.
	if len(tmpl) != 1 {
		t.Errorf("caller template mutated: len = %d, want 1", len(tmpl))
	}
}

// TestWithSecureDefaultsRespectsExplicit checks that an explicit value wins.
func TestWithSecureDefaultsRespectsExplicit(t *testing.T) {
	tmpl := []*cryptoki.Attribute{
		cryptoki.NewAttribute(cryptoki.CKA_SENSITIVE, false),
		cryptoki.NewAttribute(cryptoki.CKA_EXTRACTABLE, true),
	}
	out := withSecureDefaults(tmpl, true)

	// Exactly one of each: the caller's, not a duplicate default.
	if n := countAttr(out, cryptoki.CKA_SENSITIVE); n != 1 {
		t.Errorf("CKA_SENSITIVE count = %d, want 1", n)
	}
	if n := countAttr(out, cryptoki.CKA_EXTRACTABLE); n != 1 {
		t.Errorf("CKA_EXTRACTABLE count = %d, want 1", n)
	}
	for _, a := range out {
		if a.Type == cryptoki.CKA_SENSITIVE && len(a.Value) != 1 {
			t.Errorf("CKA_SENSITIVE value len = %d, want 1", len(a.Value))
		}
	}
}

// TestWithSecureDefaultsPublicNotPrivate checks CKA_PRIVATE is not forced on a
// public object.
func TestWithSecureDefaultsPublicNotPrivate(t *testing.T) {
	out := withSecureDefaults(nil, false)
	if hasAttribute(out, cryptoki.CKA_PRIVATE) {
		t.Error("CKA_PRIVATE added for public object")
	}
	if !hasAttribute(out, cryptoki.CKA_SENSITIVE) {
		t.Error("CKA_SENSITIVE not added")
	}
}

// TestCheckOpenClosedSession checks that a closed session reports an error.
func TestCheckOpenClosedSession(t *testing.T) {
	s := &Session{closed: true}
	if err := s.checkOpen(); err == nil {
		t.Error("checkOpen on closed session = nil, want error")
	}
	open := &Session{}
	if err := open.checkOpen(); err != nil {
		t.Errorf("checkOpen on open session = %v, want nil", err)
	}
}

// TestObjectMethodsRejectClosedSession checks that object accessors fail fast on
// a closed session instead of issuing calls on a dead handle. The session has a
// nil ctx, so a method that got past checkOpen would panic; returning an error
// proves the guard runs first.
func TestObjectMethodsRejectClosedSession(t *testing.T) {
	s := &Session{closed: true}
	o := Object{session: s, handle: 1}

	if _, err := o.Attribute(cryptoki.CKA_LABEL); err == nil {
		t.Error("Object.Attribute on closed session = nil, want error")
	}
	if _, err := o.Attributes(cryptoki.CKA_LABEL); err == nil {
		t.Error("Object.Attributes on closed session = nil, want error")
	}
	if err := o.SetAttribute(cryptoki.CKA_LABEL, []byte("x")); err == nil {
		t.Error("Object.SetAttribute on closed session = nil, want error")
	}
	if _, err := o.Copy(nil); err == nil {
		t.Error("Object.Copy on closed session = nil, want error")
	}
	if err := o.Destroy(); err == nil {
		t.Error("Object.Destroy on closed session = nil, want error")
	}
}

// TestKeyMethodsRejectClosedSession checks the key operations guard too.
func TestKeyMethodsRejectClosedSession(t *testing.T) {
	s := &Session{closed: true}
	sk := SecretKey{session: s, handle: 1}
	pub := PublicKey{session: s, handle: 2}
	priv := PrivateKey{session: s, handle: 3}

	if _, err := sk.Encrypt(nil, nil); err == nil {
		t.Error("SecretKey.Encrypt on closed session = nil, want error")
	}
	if _, err := sk.Decrypt(nil, nil); err == nil {
		t.Error("SecretKey.Decrypt on closed session = nil, want error")
	}
	if _, err := sk.Wrap(nil, Object{}); err == nil {
		t.Error("SecretKey.Wrap on closed session = nil, want error")
	}
	if _, err := sk.Unwrap(nil, nil, nil); err == nil {
		t.Error("SecretKey.Unwrap on closed session = nil, want error")
	}
	if _, err := pub.Encrypt(nil, nil); err == nil {
		t.Error("PublicKey.Encrypt on closed session = nil, want error")
	}
	if err := pub.Verify(nil, nil, nil); err == nil {
		t.Error("PublicKey.Verify on closed session = nil, want error")
	}
	if err := pub.VerifyStateless(nil, nil, nil); err == nil {
		t.Error("PublicKey.VerifyStateless on closed session = nil, want error")
	}
	if _, _, err := pub.Encapsulate(nil, nil); err == nil {
		t.Error("PublicKey.Encapsulate on closed session = nil, want error")
	}
	if _, err := priv.Sign(nil, nil); err == nil {
		t.Error("PrivateKey.Sign on closed session = nil, want error")
	}
	if _, err := priv.Decrypt(nil, nil); err == nil {
		t.Error("PrivateKey.Decrypt on closed session = nil, want error")
	}
	if _, err := priv.Derive(nil, nil); err == nil {
		t.Error("PrivateKey.Derive on closed session = nil, want error")
	}
	if _, err := priv.Decapsulate(nil, nil, nil); err == nil {
		t.Error("PrivateKey.Decapsulate on closed session = nil, want error")
	}
}

// TestCloseIdempotent checks that Close can be called twice without error and
// that the second call does not touch the (nil) ctx.
func TestCloseIdempotent(t *testing.T) {
	s := &Session{closed: true}
	if err := s.Close(); err != nil {
		t.Errorf("Close on already-closed session = %v, want nil", err)
	}
}

func countAttr(tmpl []*cryptoki.Attribute, typ uint) int {
	n := 0
	for _, a := range tmpl {
		if a != nil && a.Type == typ {
			n++
		}
	}
	return n
}
