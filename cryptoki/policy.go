// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"fmt"
	"sync"
)

// MechanismPolicy decides whether a mechanism may be used. It is consulted by
// NewMechanism and NewMechanismWithParams before a Mechanism is built, so a
// policy violation is reported at construction time rather than by the token.
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
