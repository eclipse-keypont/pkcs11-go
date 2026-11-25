// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"fmt"
	"sync"
)

// MechanismPolicy decides whether a mechanism may be used. It is consulted by
// NewMechanism and NewMechanismWithParams before a Mechanism is built, so a
// policy violation is reported at construction time rather than by the token,
// and again whenever a Mechanism is passed to an operation, so a Mechanism
// built as a struct literal cannot bypass it.
//
// At operation time the policy also judges the digests a parameter names: the
// OAEP and PSS hash and MGF, the KDF of ECDH1, ECMQV and the ECDH AES key
// wraps, the PRF of HKDF and SP 800-108, and the hash of HashML-DSA and
// HashSLH-DSA. A structured parameter reports them itself; a raw Parameter is
// decoded with the platform's C struct layouts. While a policy is installed, a
// raw Parameter that cannot be decoded is refused: one too short for its
// struct, and one for CKM_RSA_AES_KEY_WRAP, whose OAEP digests sit behind a
// pointer.
//
// A nil policy (the default) permits every mechanism: the binding does not
// second-guess a caller who deliberately selects a legacy algorithm. Install a
// policy with SetMechanismPolicy to reject weak mechanisms process-wide.
type MechanismPolicy interface {
	// Allow reports whether the mechanism type may be used. A non-nil error is
	// returned to the caller of NewMechanism/NewMechanismWithParams.
	Allow(mechanism uint) error
}

// MechanismPolicyFunc adapts a function to the MechanismPolicy interface.
type MechanismPolicyFunc func(mechanism uint) error

// Allow implements MechanismPolicy.
func (f MechanismPolicyFunc) Allow(mechanism uint) error { return f(mechanism) }

var (
	policyMu sync.RWMutex
	policy   MechanismPolicy
)

// SetMechanismPolicy installs a process-wide mechanism policy. Pass nil to
// remove the policy and permit every mechanism again. It is safe to call from
// multiple goroutines; the policy is read under a lock on every mechanism
// construction.
func SetMechanismPolicy(p MechanismPolicy) {
	policyMu.Lock()
	defer policyMu.Unlock()
	policy = p
}

// checkMechanism consults the installed policy, if any.
func checkMechanism(mechanism uint) error {
	policyMu.RLock()
	p := policy
	policyMu.RUnlock()
	if p == nil {
		return nil
	}
	return p.Allow(mechanism)
}

// checkMechanismUse consults the installed policy for m and for every digest
// mechanism its parameter names, whether structured (hashMechanisms) or raw
// (rawParamDigests). It runs when a Mechanism is handed to the module, so a
// Mechanism built as a struct literal, or with a weak hash inside an otherwise
// strong parameter block, is still subject to the policy.
func checkMechanismUse(m *Mechanism) error {
	policyMu.RLock()
	p := policy
	policyMu.RUnlock()
	if p == nil {
		return nil
	}
	if err := p.Allow(m.Mechanism); err != nil {
		return err
	}
	var digests []uint
	switch params := m.params.(type) {
	case nil:
		var err error
		if digests, err = rawParamDigests(m.Mechanism, m.Parameter); err != nil {
			return err
		}
	case interface{ hashMechanisms() []uint }:
		digests = params.hashMechanisms()
	}
	for _, d := range digests {
		if err := p.Allow(d); err != nil {
			return err
		}
	}
	return nil
}

// mgfHash maps a CKG_MGF1_* mask generation function to the digest mechanism
// it runs on, so the policy can judge an OAEP/PSS MGF like any other hash.
var mgfHash = map[uint]uint{
	CKG_MGF1_SHA1:     CKM_SHA_1,
	CKG_MGF1_SHA224:   CKM_SHA224,
	CKG_MGF1_SHA256:   CKM_SHA256,
	CKG_MGF1_SHA384:   CKM_SHA384,
	CKG_MGF1_SHA512:   CKM_SHA512,
	CKG_MGF1_SHA3_224: CKM_SHA3_224,
	CKG_MGF1_SHA3_256: CKM_SHA3_256,
	CKG_MGF1_SHA3_384: CKM_SHA3_384,
	CKG_MGF1_SHA3_512: CKM_SHA3_512,
}

// kdfHash maps a CKD_* key derivation function to the digest mechanism it
// runs on. CKD_NULL and KDFs without a CKM_ digest counterpart are absent.
var kdfHash = map[uint]uint{
	CKD_SHA1_KDF:             CKM_SHA_1,
	CKD_SHA1_KDF_ASN1:        CKM_SHA_1,
	CKD_SHA1_KDF_CONCATENATE: CKM_SHA_1,
	CKD_SHA1_KDF_SP800:       CKM_SHA_1,
	CKD_SHA224_KDF:           CKM_SHA224,
	CKD_SHA224_KDF_SP800:     CKM_SHA224,
	CKD_SHA256_KDF:           CKM_SHA256,
	CKD_SHA256_KDF_SP800:     CKM_SHA256,
	CKD_SHA384_KDF:           CKM_SHA384,
	CKD_SHA384_KDF_SP800:     CKM_SHA384,
	CKD_SHA512_KDF:           CKM_SHA512,
	CKD_SHA512_KDF_SP800:     CKM_SHA512,
	CKD_SHA3_224_KDF:         CKM_SHA3_224,
	CKD_SHA3_224_KDF_SP800:   CKM_SHA3_224,
	CKD_SHA3_256_KDF:         CKM_SHA3_256,
	CKD_SHA3_256_KDF_SP800:   CKM_SHA3_256,
	CKD_SHA3_384_KDF:         CKM_SHA3_384,
	CKD_SHA3_384_KDF_SP800:   CKM_SHA3_384,
	CKD_SHA3_512_KDF:         CKM_SHA3_512,
	CKD_SHA3_512_KDF_SP800:   CKM_SHA3_512,
}

// weakMechanisms is the set of mechanisms a RejectWeakMechanisms policy refuses:
// MD2/MD5/SHA-1 digests and their HMAC/RSA/DSA/ECDSA variants, single-DES and
// RC2/RC4 ciphers, and the SSLv3 MACs. These are broken or deprecated and must
// not be used for new work.
var weakMechanisms = map[uint]string{
	CKM_MD2:                  "MD2",
	CKM_MD2_HMAC:             "MD2-HMAC",
	CKM_MD2_HMAC_GENERAL:     "MD2-HMAC-GENERAL",
	CKM_MD5:                  "MD5",
	CKM_MD5_HMAC:             "MD5-HMAC",
	CKM_MD5_HMAC_GENERAL:     "MD5-HMAC-GENERAL",
	CKM_MD5_RSA_PKCS:         "MD5-RSA-PKCS",
	CKM_MD5_KEY_DERIVATION:   "MD5-KEY-DERIVATION",
	CKM_SHA_1:                "SHA-1",
	CKM_SHA_1_HMAC:           "SHA-1-HMAC",
	CKM_SHA_1_HMAC_GENERAL:   "SHA-1-HMAC-GENERAL",
	CKM_SHA1_RSA_PKCS:        "SHA1-RSA-PKCS",
	CKM_SHA1_RSA_PKCS_PSS:    "SHA1-RSA-PKCS-PSS",
	CKM_SHA1_RSA_X9_31:       "SHA1-RSA-X9.31",
	CKM_DSA_SHA1:             "DSA-SHA1",
	CKM_ECDSA_SHA1:           "ECDSA-SHA1",
	CKM_SHA1_KEY_DERIVATION:  "SHA1-KEY-DERIVATION",
	CKM_DES_KEY_GEN:          "DES-KEY-GEN",
	CKM_DES_ECB:              "DES-ECB",
	CKM_DES_CBC:              "DES-CBC",
	CKM_DES_MAC:              "DES-MAC",
	CKM_DES_MAC_GENERAL:      "DES-MAC-GENERAL",
	CKM_DES_CBC_PAD:          "DES-CBC-PAD",
	CKM_DES2_KEY_GEN:         "DES2-KEY-GEN",
	CKM_RC2_KEY_GEN:          "RC2-KEY-GEN",
	CKM_RC2_ECB:              "RC2-ECB",
	CKM_RC2_CBC:              "RC2-CBC",
	CKM_RC2_MAC:              "RC2-MAC",
	CKM_RC2_MAC_GENERAL:      "RC2-MAC-GENERAL",
	CKM_RC4_KEY_GEN:          "RC4-KEY-GEN",
	CKM_RC4:                  "RC4",
	CKM_SSL3_MD5_MAC:         "SSL3-MD5-MAC",
	CKM_SSL3_SHA1_MAC:        "SSL3-SHA1-MAC",
	CKM_PBE_MD2_DES_CBC:      "PBE-MD2-DES-CBC",
	CKM_PBE_MD5_DES_CBC:      "PBE-MD5-DES-CBC",
	CKM_PBE_SHA1_RC4_128:     "PBE-SHA1-RC4-128",
	CKM_PBE_SHA1_RC4_40:      "PBE-SHA1-RC4-40",
	CKM_PBE_SHA1_RC2_128_CBC: "PBE-SHA1-RC2-128-CBC",
	CKM_PBE_SHA1_RC2_40_CBC:  "PBE-SHA1-RC2-40-CBC",
}

// RejectWeakMechanisms is a MechanismPolicy that refuses the broken or
// deprecated mechanisms in weakMechanisms (MD2/MD5/SHA-1, single-DES, RC2/RC4,
// SSLv3 MACs). Install it with SetMechanismPolicy to make the binding fail
// closed on weak algorithm selection.
func RejectWeakMechanisms(mechanism uint) error {
	if name, ok := weakMechanisms[mechanism]; ok {
		return fmt.Errorf("cryptoki: mechanism %#x (%s) is weak and rejected by policy", mechanism, name)
	}
	return nil
}
