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
		CKM_MD2_RSA_PKCS,
		CKM_RIPEMD128_RSA_PKCS,
		CKM_RC2_CBC_PAD,
		CKM_DES_OFB64,
		CKM_DES_CFB8,
		CKM_CDMF_CBC,
		CKM_CAST3_CBC,
		CKM_SKIPJACK_CBC64,
		CKM_SSL3_MASTER_KEY_DERIVE,
		CKM_TLS_PRF,
		CKM_PBE_SHA1_DES3_EDE_CBC,
		CKM_PBA_SHA1_WITH_SHA1_HMAC,
		CKM_SHA_1_KEY_GEN,
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
		CKM_DES3_CBC,
		CKM_TLS12_KDF,
		CKM_VENDOR_DEFINED | 1,
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

// TestCMechanismEnforcesPolicyOnLiteral checks that a Mechanism built as a
// struct literal, which skips the constructors, is still rejected when it is
// marshalled for an operation.
func TestCMechanismEnforcesPolicyOnLiteral(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	mech, freeMech, err := cMechanism(&Mechanism{Mechanism: CKM_MD5})
	if err == nil {
		freeMech()
		t.Fatal("cMechanism(&Mechanism{MD5}) = nil error under RejectWeakMechanisms")
	}
	if mech != nil {
		t.Errorf("cMechanism returned a mechanism alongside the policy error")
	}
}

// TestCMechanismAllowsStrongUnderPolicy checks a strong mechanism still
// marshals when the policy is installed.
func TestCMechanismAllowsStrongUnderPolicy(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	mech, freeMech, err := cMechanism(&Mechanism{Mechanism: CKM_AES_CBC_PAD, Parameter: make([]byte, 16)})
	if err != nil {
		t.Fatalf("cMechanism(AES_CBC_PAD) = %v, want nil", err)
	}
	defer freeMech()
	if mech == nil {
		t.Fatal("cMechanism(AES_CBC_PAD) returned a nil mechanism")
	}
}

// TestPolicyChecksParameterHashes checks that the digests named inside a
// structured parameter are judged by the policy, so a strong outer mechanism
// cannot carry a weak hash, MGF or KDF.
func TestPolicyChecksParameterHashes(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	weak := map[string]*Mechanism{
		"OAEP hash SHA-1":  {Mechanism: CKM_RSA_PKCS_OAEP, params: NewOAEPParams(CKM_SHA_1, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nil)},
		"OAEP MGF1-SHA1":   {Mechanism: CKM_RSA_PKCS_OAEP, params: NewOAEPParams(CKM_SHA256, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, nil)},
		"PSS hash SHA-1":   {Mechanism: CKM_RSA_PKCS_PSS, params: NewPSSParams(CKM_SHA_1, CKG_MGF1_SHA256, 32)},
		"PSS MGF1-SHA1":    {Mechanism: CKM_RSA_PKCS_PSS, params: NewPSSParams(CKM_SHA256, CKG_MGF1_SHA1, 32)},
		"ECDH1 SHA-1 KDF":  {Mechanism: CKM_ECDH1_DERIVE, params: NewECDH1DeriveParams(CKD_SHA1_KDF, nil, []byte{4})},
		"ECDH1 SP800 SHA1": {Mechanism: CKM_ECDH1_DERIVE, params: NewECDH1DeriveParams(CKD_SHA1_KDF_SP800, nil, []byte{4})},
	}
	for name, m := range weak {
		if err := checkMechanismUse(m); err == nil {
			t.Errorf("%s: checkMechanismUse = nil, want policy error", name)
		}
	}

	strong := map[string]*Mechanism{
		"OAEP SHA-256":    {Mechanism: CKM_RSA_PKCS_OAEP, params: NewOAEPParams(CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, nil)},
		"PSS SHA-384":     {Mechanism: CKM_RSA_PKCS_PSS, params: NewPSSParams(CKM_SHA384, CKG_MGF1_SHA384, 48)},
		"ECDH1 CKD_NULL":  {Mechanism: CKM_ECDH1_DERIVE, params: NewECDH1DeriveParams(CKD_NULL, nil, []byte{4})},
		"ECDH1 SHA-256":   {Mechanism: CKM_ECDH1_DERIVE, params: NewECDH1DeriveParams(CKD_SHA256_KDF, nil, []byte{4})},
		"GCM (no hashes)": {Mechanism: CKM_AES_GCM, params: nil},
	}
	for name, m := range strong {
		if err := checkMechanismUse(m); err != nil {
			t.Errorf("%s: checkMechanismUse = %v, want nil", name, err)
		}
	}

}

// TestNewMechanismWithParamsLeavesDigestsToUse checks that a digest the policy
// rejects, inside an otherwise allowed mechanism's parameter, does not make
// NewMechanismWithParams panic, since the digest may come from data, and that
// the rejection is an error when the Mechanism is used.
func TestNewMechanismWithParamsLeavesDigestsToUse(t *testing.T) {
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	var m *Mechanism
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("NewMechanismWithParams(OAEP, SHA-1) panicked: %v", r)
			}
		}()
		m = NewMechanismWithParams(CKM_RSA_PKCS_OAEP, NewOAEPParams(CKM_SHA_1, CKG_MGF1_SHA1, CKZ_DATA_SPECIFIED, nil))
	}()
	if err := checkMechanismUse(m); err == nil {
		t.Fatal("using OAEP with SHA-1 under RejectWeakMechanisms = nil, want the policy error")
	}
	if _, _, err := cMechanism(m); err == nil {
		t.Fatal("cMechanism(OAEP, SHA-1) under RejectWeakMechanisms = nil, want the policy error")
	}
}

// rawParam builds the raw parameter of mechanism, the bytes of its CK_*_PARAMS
// struct, with values written into the digest fields the policy decodes, in
// order, and every other byte zero.
func rawParam(t *testing.T, mechanism uint, values ...uint) []byte {
	t.Helper()
	l, ok := rawLayouts[mechanism]
	if !ok || len(values) != len(l.fields) {
		t.Fatalf("rawParam(%#x): %d values for %d digest fields", mechanism, len(values), len(l.fields))
	}
	p := make([]byte, l.size)
	for i, f := range l.fields {
		copy(p[f.offset:], ckULong(values[i]))
	}
	return p
}

// TestPolicyChecksRawParameterDigests checks that the digests named inside a
// raw Parameter are judged like those of a structured one, and that a raw
// Parameter the policy cannot decode is refused.
func TestPolicyChecksRawParameterDigests(t *testing.T) {
	// The CK_RSA_PKCS_PSS_PARAMS layout is three CK_ULONGs on every platform,
	// so it is built here independently of rawLayouts.
	pss := func(hash, mgf uint) []byte {
		return append(append(ckULong(hash), ckULong(mgf)...), ckULong(32)...)
	}
	weak := map[string]*Mechanism{
		"PSS hash SHA-1":          {Mechanism: CKM_SHA256_RSA_PKCS_PSS, Parameter: pss(CKM_SHA_1, CKG_MGF1_SHA256)},
		"PSS MGF1-SHA1":           {Mechanism: CKM_RSA_PKCS_PSS, Parameter: pss(CKM_SHA256, CKG_MGF1_SHA1)},
		"OAEP hash SHA-1":         {Mechanism: CKM_RSA_PKCS_OAEP, Parameter: rawParam(t, CKM_RSA_PKCS_OAEP, CKM_SHA_1, CKG_MGF1_SHA256)},
		"OAEP MGF1-SHA1":          {Mechanism: CKM_RSA_PKCS_OAEP, Parameter: rawParam(t, CKM_RSA_PKCS_OAEP, CKM_SHA256, CKG_MGF1_SHA1)},
		"ECDH1 SHA-1 KDF":         {Mechanism: CKM_ECDH1_DERIVE, Parameter: rawParam(t, CKM_ECDH1_DERIVE, CKD_SHA1_KDF)},
		"ECDH1 cofactor SHA-1":    {Mechanism: CKM_ECDH1_COFACTOR_DERIVE, Parameter: rawParam(t, CKM_ECDH1_COFACTOR_DERIVE, CKD_SHA1_KDF_SP800)},
		"ECMQV SHA-1 KDF":         {Mechanism: CKM_ECMQV_DERIVE, Parameter: rawParam(t, CKM_ECMQV_DERIVE, CKD_SHA1_KDF)},
		"ECDH AES wrap SHA-1":     {Mechanism: CKM_ECDH_AES_KEY_WRAP, Parameter: rawParam(t, CKM_ECDH_AES_KEY_WRAP, CKD_SHA1_KDF)},
		"HKDF SHA-1":              {Mechanism: CKM_HKDF_DERIVE, Parameter: rawParam(t, CKM_HKDF_DERIVE, CKM_SHA_1)},
		"HKDF data SHA-1":         {Mechanism: CKM_HKDF_DATA, Parameter: rawParam(t, CKM_HKDF_DATA, CKM_SHA_1)},
		"SP800-108 HMAC-SHA1":     {Mechanism: CKM_SP800_108_COUNTER_KDF, Parameter: rawParam(t, CKM_SP800_108_COUNTER_KDF, CKM_SHA_1_HMAC)},
		"SP800-108 feedback SHA1": {Mechanism: CKM_SP800_108_FEEDBACK_KDF, Parameter: rawParam(t, CKM_SP800_108_FEEDBACK_KDF, CKM_SHA_1_HMAC)},
		"HashML-DSA SHA-1":        {Mechanism: CKM_HASH_ML_DSA, Parameter: rawParam(t, CKM_HASH_ML_DSA, CKM_SHA_1)},
		"HashSLH-DSA SHA-1":       {Mechanism: CKM_HASH_SLH_DSA, Parameter: rawParam(t, CKM_HASH_SLH_DSA, CKM_SHA_1)},
		// Fail closed: the policy cannot see the digests.
		"PSS truncated":     {Mechanism: CKM_RSA_PKCS_PSS, Parameter: ckULong(CKM_SHA256)},
		"OAEP no parameter": {Mechanism: CKM_RSA_PKCS_OAEP},
		"RSA AES key wrap":  {Mechanism: CKM_RSA_AES_KEY_WRAP, Parameter: make([]byte, rawLayouts[CKM_RSA_AES_KEY_WRAP].size)},
	}
	strong := map[string]*Mechanism{
		"PSS SHA-256":            {Mechanism: CKM_SHA256_RSA_PKCS_PSS, Parameter: pss(CKM_SHA256, CKG_MGF1_SHA256)},
		"OAEP SHA-256":           {Mechanism: CKM_RSA_PKCS_OAEP, Parameter: rawParam(t, CKM_RSA_PKCS_OAEP, CKM_SHA256, CKG_MGF1_SHA256)},
		"ECDH1 CKD_NULL":         {Mechanism: CKM_ECDH1_DERIVE, Parameter: rawParam(t, CKM_ECDH1_DERIVE, CKD_NULL)},
		"HKDF SHA-256":           {Mechanism: CKM_HKDF_DERIVE, Parameter: rawParam(t, CKM_HKDF_DERIVE, CKM_SHA256)},
		"SP800-108 HMAC-SHA256":  {Mechanism: CKM_SP800_108_COUNTER_KDF, Parameter: rawParam(t, CKM_SP800_108_COUNTER_KDF, CKM_SHA256_HMAC)},
		"HashML-DSA SHA-512":     {Mechanism: CKM_HASH_ML_DSA, Parameter: rawParam(t, CKM_HASH_ML_DSA, CKM_SHA512)},
		"CBC IV (no digests)":    {Mechanism: CKM_AES_CBC, Parameter: make([]byte, 16)},
		"PSS longer than struct": {Mechanism: CKM_RSA_PKCS_PSS, Parameter: append(pss(CKM_SHA256, CKG_MGF1_SHA256), 0)},
	}

	SetMechanismPolicy(nil)
	t.Cleanup(func() { SetMechanismPolicy(nil) })
	for name, m := range weak {
		if err := checkMechanismUse(m); err != nil {
			t.Errorf("%s: checkMechanismUse without a policy = %v, want nil", name, err)
		}
	}

	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	for name, m := range weak {
		if err := checkMechanismUse(m); err == nil {
			t.Errorf("%s: checkMechanismUse = nil, want policy error", name)
		}
	}
	for name, m := range strong {
		if err := checkMechanismUse(m); err != nil {
			t.Errorf("%s: checkMechanismUse = %v, want nil", name, err)
		}
	}
}

// TestIntegrationPolicyRawPSSParameter signs with a raw PSS parameter under
// RejectWeakMechanisms. A SHA-256 parameter must sign, which shows the layout
// the policy decodes is the one the module reads, and a SHA-1 one must be
// refused by the binding before the module sees it.
func TestIntegrationPolicyRawPSSParameter(t *testing.T) {
	sh := requireSession(t)
	pub, priv, err := genRSAKeyPairRaw(t, sh)
	if err != nil {
		t.Fatalf("GenerateKeyPair(RSA): %v", err)
	}
	SetMechanismPolicy(MechanismPolicyFunc(RejectWeakMechanisms))
	t.Cleanup(func() { SetMechanismPolicy(nil) })

	pss := func(hash, mgf uint) *Mechanism {
		return &Mechanism{
			Mechanism: CKM_SHA256_RSA_PKCS_PSS,
			Parameter: append(append(ckULong(hash), ckULong(mgf)...), ckULong(32)...),
		}
	}
	msg := []byte("raw PSS parameter")
	if err := testCtx.SignInit(sh, pss(CKM_SHA256, CKG_MGF1_SHA256), priv); err != nil {
		t.Fatalf("SignInit(raw PSS SHA-256): %v", err)
	}
	sig, err := testCtx.Sign(sh, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verify := NewMechanismWithParams(CKM_SHA256_RSA_PKCS_PSS, NewPSSParams(CKM_SHA256, CKG_MGF1_SHA256, 32))
	if err := testCtx.VerifyInit(sh, verify, pub); err != nil {
		t.Fatalf("VerifyInit: %v", err)
	}
	if err := testCtx.Verify(sh, msg, sig); err != nil {
		t.Fatalf("Verify of the raw-parameter signature: %v", err)
	}

	for _, m := range []*Mechanism{pss(CKM_SHA_1, CKG_MGF1_SHA256), pss(CKM_SHA256, CKG_MGF1_SHA1)} {
		err := testCtx.SignInit(sh, m, priv)
		var rv Error
		if err == nil || errors.As(err, &rv) {
			t.Fatalf("SignInit(raw PSS with SHA-1) = %v, want the policy to refuse it", err)
		}
	}
}
