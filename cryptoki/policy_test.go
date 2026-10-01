// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"errors"
	"testing"
)

// TestRejectWeakMechanismsRejectsKnownWeak checks that every mechanism in the
// weak set is refused and that a strong mechanism is allowed.
func TestRejectWeakMechanismsRejectsKnownWeak(t *testing.T) {
	weak := []uint{
		CKM_MD5,
		CKM_SHA_1,
		CKM_SHA1_RSA_PKCS,
		CKM_DES_CBC,
		CKM_RC4,
		CKM_SSL3_SHA1_MAC,
		CKM_PBE_SHA1_RC4_128,
	}
	for _, m := range weak {
		if err := RejectWeakMechanisms(m); err == nil {
			t.Errorf("RejectWeakMechanisms(%#x) = nil, want error", m)
		}
	}

	strong := []uint{
		CKM_SHA256,
		CKM_SHA256_RSA_PKCS,
		CKM_AES_CBC,
		CKM_AES_GCM,
		CKM_ECDSA,
	}
	for _, m := range strong {
		if err := RejectWeakMechanisms(m); err != nil {
			t.Errorf("RejectWeakMechanisms(%#x) = %v, want nil", m, err)
		}
	}
}

// TestSetMechanismPolicyNilAllowsAll checks that the default (nil) policy
// permits every mechanism, including weak ones.
func TestSetMechanismPolicyNilAllowsAll(t *testing.T) {
	SetMechanismPolicy(nil)
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	if err := checkMechanism(CKM_MD5); err != nil {
		t.Errorf("checkMechanism(MD5) with nil policy = %v, want nil", err)
	}
}

// TestSetMechanismPolicyInstalled checks that an installed policy is consulted
// by checkMechanism and can be removed again.
func TestSetMechanismPolicyInstalled(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	if err := checkMechanism(CKM_MD5); err == nil {
		t.Error("checkMechanism(MD5) with RejectWeakMechanisms = nil, want error")
	}
	if err := checkMechanism(CKM_AES_GCM); err != nil {
		t.Errorf("checkMechanism(AES_GCM) with RejectWeakMechanisms = %v, want nil", err)
	}

	SetMechanismPolicy(nil)
	if err := checkMechanism(CKM_MD5); err != nil {
		t.Errorf("checkMechanism(MD5) after removing policy = %v, want nil", err)
	}
}

// TestNewMechanismPanicsOnPolicyViolation checks that a rejected mechanism
// panics at construction time.
func TestNewMechanismPanicsOnPolicyViolation(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	defer func() {
		if r := recover(); r == nil {
			t.Error("NewMechanism(MD5) did not panic under RejectWeakMechanisms")
		}
	}()
	_ = NewMechanism(CKM_MD5, nil)
}

// TestNewMechanismWithParamsPanicsOnPolicyViolation checks the params
// constructor enforces the policy too.
func TestNewMechanismWithParamsPanicsOnPolicyViolation(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	defer func() {
		if r := recover(); r == nil {
			t.Error("NewMechanismWithParams(MD5) did not panic under RejectWeakMechanisms")
		}
	}()
	_ = NewMechanismWithParams(CKM_MD5, nil)
}

// TestNewMechanismAllowsStrongUnderPolicy checks a strong mechanism still
// constructs when the policy is installed.
func TestNewMechanismAllowsStrongUnderPolicy(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	m := NewMechanism(CKM_AES_GCM, nil)
	if m == nil || m.Mechanism != CKM_AES_GCM {
		t.Fatalf("NewMechanism(AES_GCM) = %+v, want mechanism %#x", m, CKM_AES_GCM)
	}
}

// TestMechanismPolicyFuncError checks the adapter forwards the error verbatim.
func TestMechanismPolicyFuncError(t *testing.T) {
	sentinel := errors.New("nope")
	p := MechanismPolicyFunc(func(uint) error { return sentinel })
	if err := p.Allow(CKM_AES_GCM); !errors.Is(err, sentinel) {
		t.Errorf("Allow = %v, want %v", err, sentinel)
	}
}
