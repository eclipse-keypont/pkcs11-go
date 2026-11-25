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
// Only at operation time, where a rejection is an error rather than a panic,
// does the policy also judge the digests a parameter names: the
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

// weakMechanisms is the set of mechanisms a RejectWeakMechanisms policy refuses,
// because they are broken or deprecated and must not be used for new work:
//
//   - MD2, MD5, SHA-1 and RIPEMD-128, and every mechanism built on them: their
//     HMACs, RSA/DSA/ECDSA signatures, key derivations, the SSLv3 MACs and the
//     password-based schemes (PBE, PBA);
//   - single DES in every mode, two-key triple DES, and CDMF;
//   - ciphers with keys of 64 bits or less, or broken outright: RC2, RC4, CAST,
//     CAST3, SKIPJACK, the KEA exchange, and the LYNKS and SET key wraps;
//   - the SSLv3 and TLS 1.0/1.1 key derivations and PRF, which run on MD5 and
//     SHA-1.
//
// Three-key triple DES, CAST5, IDEA and Blowfish are legacy but not broken, and
// stay allowed, as do vendor-defined mechanisms, whose strength the binding
// cannot know.
var weakMechanisms = map[uint]string{
	// MD2, MD5, SHA-1 and RIPEMD-128.
	CKM_MD2:                    "MD2",
	CKM_MD2_HMAC:               "MD2-HMAC",
	CKM_MD2_HMAC_GENERAL:       "MD2-HMAC-GENERAL",
	CKM_MD2_RSA_PKCS:           "MD2-RSA-PKCS",
	CKM_MD2_KEY_DERIVATION:     "MD2-KEY-DERIVATION",
	CKM_MD5:                    "MD5",
	CKM_MD5_HMAC:               "MD5-HMAC",
	CKM_MD5_HMAC_GENERAL:       "MD5-HMAC-GENERAL",
	CKM_MD5_RSA_PKCS:           "MD5-RSA-PKCS",
	CKM_MD5_KEY_DERIVATION:     "MD5-KEY-DERIVATION",
	CKM_SHA_1:                  "SHA-1",
	CKM_SHA_1_HMAC:             "SHA-1-HMAC",
	CKM_SHA_1_HMAC_GENERAL:     "SHA-1-HMAC-GENERAL",
	CKM_SHA_1_KEY_GEN:          "SHA-1-KEY-GEN",
	CKM_SHA1_RSA_PKCS:          "SHA1-RSA-PKCS",
	CKM_SHA1_RSA_PKCS_PSS:      "SHA1-RSA-PKCS-PSS",
	CKM_SHA1_RSA_X9_31:         "SHA1-RSA-X9.31",
	CKM_DSA_SHA1:               "DSA-SHA1",
	CKM_ECDSA_SHA1:             "ECDSA-SHA1",
	CKM_SHA1_KEY_DERIVATION:    "SHA1-KEY-DERIVATION",
	CKM_RIPEMD128:              "RIPEMD128",
	CKM_RIPEMD128_HMAC:         "RIPEMD128-HMAC",
	CKM_RIPEMD128_HMAC_GENERAL: "RIPEMD128-HMAC-GENERAL",
	CKM_RIPEMD128_RSA_PKCS:     "RIPEMD128-RSA-PKCS",
	CKM_SSL3_MD5_MAC:           "SSL3-MD5-MAC",
	CKM_SSL3_SHA1_MAC:          "SSL3-SHA1-MAC",

	// Password-based schemes on the above.
	CKM_PBE_MD2_DES_CBC:         "PBE-MD2-DES-CBC",
	CKM_PBE_MD5_DES_CBC:         "PBE-MD5-DES-CBC",
	CKM_PBE_MD5_CAST_CBC:        "PBE-MD5-CAST-CBC",
	CKM_PBE_MD5_CAST3_CBC:       "PBE-MD5-CAST3-CBC",
	CKM_PBE_MD5_CAST128_CBC:     "PBE-MD5-CAST128-CBC",
	CKM_PBE_SHA1_CAST128_CBC:    "PBE-SHA1-CAST128-CBC",
	CKM_PBE_SHA1_RC4_128:        "PBE-SHA1-RC4-128",
	CKM_PBE_SHA1_RC4_40:         "PBE-SHA1-RC4-40",
	CKM_PBE_SHA1_DES3_EDE_CBC:   "PBE-SHA1-DES3-EDE-CBC",
	CKM_PBE_SHA1_DES2_EDE_CBC:   "PBE-SHA1-DES2-EDE-CBC",
	CKM_PBE_SHA1_RC2_128_CBC:    "PBE-SHA1-RC2-128-CBC",
	CKM_PBE_SHA1_RC2_40_CBC:     "PBE-SHA1-RC2-40-CBC",
	CKM_PBA_SHA1_WITH_SHA1_HMAC: "PBA-SHA1-WITH-SHA1-HMAC",

	// Single DES, two-key triple DES and CDMF.
	CKM_DES_KEY_GEN:          "DES-KEY-GEN",
	CKM_DES_ECB:              "DES-ECB",
	CKM_DES_CBC:              "DES-CBC",
	CKM_DES_CBC_PAD:          "DES-CBC-PAD",
	CKM_DES_MAC:              "DES-MAC",
	CKM_DES_MAC_GENERAL:      "DES-MAC-GENERAL",
	CKM_DES_OFB64:            "DES-OFB64",
	CKM_DES_OFB8:             "DES-OFB8",
	CKM_DES_CFB64:            "DES-CFB64",
	CKM_DES_CFB8:             "DES-CFB8",
	CKM_DES_ECB_ENCRYPT_DATA: "DES-ECB-ENCRYPT-DATA",
	CKM_DES_CBC_ENCRYPT_DATA: "DES-CBC-ENCRYPT-DATA",
	CKM_DES2_KEY_GEN:         "DES2-KEY-GEN",
	CKM_CDMF_KEY_GEN:         "CDMF-KEY-GEN",
	CKM_CDMF_ECB:             "CDMF-ECB",
	CKM_CDMF_CBC:             "CDMF-CBC",
	CKM_CDMF_CBC_PAD:         "CDMF-CBC-PAD",
	CKM_CDMF_MAC:             "CDMF-MAC",
	CKM_CDMF_MAC_GENERAL:     "CDMF-MAC-GENERAL",

	// Short-key or broken ciphers and key wraps.
	CKM_RC2_KEY_GEN:           "RC2-KEY-GEN",
	CKM_RC2_ECB:               "RC2-ECB",
	CKM_RC2_CBC:               "RC2-CBC",
	CKM_RC2_CBC_PAD:           "RC2-CBC-PAD",
	CKM_RC2_MAC:               "RC2-MAC",
	CKM_RC2_MAC_GENERAL:       "RC2-MAC-GENERAL",
	CKM_RC4_KEY_GEN:           "RC4-KEY-GEN",
	CKM_RC4:                   "RC4",
	CKM_CAST_KEY_GEN:          "CAST-KEY-GEN",
	CKM_CAST_ECB:              "CAST-ECB",
	CKM_CAST_CBC:              "CAST-CBC",
	CKM_CAST_CBC_PAD:          "CAST-CBC-PAD",
	CKM_CAST_MAC:              "CAST-MAC",
	CKM_CAST_MAC_GENERAL:      "CAST-MAC-GENERAL",
	CKM_CAST3_KEY_GEN:         "CAST3-KEY-GEN",
	CKM_CAST3_ECB:             "CAST3-ECB",
	CKM_CAST3_CBC:             "CAST3-CBC",
	CKM_CAST3_CBC_PAD:         "CAST3-CBC-PAD",
	CKM_CAST3_MAC:             "CAST3-MAC",
	CKM_CAST3_MAC_GENERAL:     "CAST3-MAC-GENERAL",
	CKM_SKIPJACK_KEY_GEN:      "SKIPJACK-KEY-GEN",
	CKM_SKIPJACK_ECB64:        "SKIPJACK-ECB64",
	CKM_SKIPJACK_CBC64:        "SKIPJACK-CBC64",
	CKM_SKIPJACK_OFB64:        "SKIPJACK-OFB64",
	CKM_SKIPJACK_CFB64:        "SKIPJACK-CFB64",
	CKM_SKIPJACK_CFB32:        "SKIPJACK-CFB32",
	CKM_SKIPJACK_CFB16:        "SKIPJACK-CFB16",
	CKM_SKIPJACK_CFB8:         "SKIPJACK-CFB8",
	CKM_SKIPJACK_WRAP:         "SKIPJACK-WRAP",
	CKM_SKIPJACK_PRIVATE_WRAP: "SKIPJACK-PRIVATE-WRAP",
	CKM_SKIPJACK_RELAYX:       "SKIPJACK-RELAYX",
	CKM_KEA_KEY_PAIR_GEN:      "KEA-KEY-PAIR-GEN",
	CKM_KEA_KEY_DERIVE:        "KEA-KEY-DERIVE",
	CKM_KEA_DERIVE:            "KEA-DERIVE",
	CKM_KEY_WRAP_LYNKS:        "KEY-WRAP-LYNKS",
	CKM_KEY_WRAP_SET_OAEP:     "KEY-WRAP-SET-OAEP",

	// SSLv3 and TLS 1.0/1.1 key derivation.
	CKM_SSL3_PRE_MASTER_KEY_GEN:   "SSL3-PRE-MASTER-KEY-GEN",
	CKM_SSL3_MASTER_KEY_DERIVE:    "SSL3-MASTER-KEY-DERIVE",
	CKM_SSL3_MASTER_KEY_DERIVE_DH: "SSL3-MASTER-KEY-DERIVE-DH",
	CKM_SSL3_KEY_AND_MAC_DERIVE:   "SSL3-KEY-AND-MAC-DERIVE",
	CKM_TLS_MASTER_KEY_DERIVE:     "TLS-MASTER-KEY-DERIVE",
	CKM_TLS_MASTER_KEY_DERIVE_DH:  "TLS-MASTER-KEY-DERIVE-DH",
	CKM_TLS_KEY_AND_MAC_DERIVE:    "TLS-KEY-AND-MAC-DERIVE",
	CKM_TLS_PRF:                   "TLS-PRF",
}

// RejectWeakMechanisms is a MechanismPolicy that refuses the broken or
// deprecated mechanisms in weakMechanisms (MD2/MD5/SHA-1 and what is built on
// them, single DES, short-key ciphers, the SSLv3 and TLS 1.0/1.1 PRFs). Install
// it with SetMechanismPolicy to make the binding fail closed on weak algorithm
// selection. It is a deny-list: a mechanism it does not name, including any
// vendor-defined one, is allowed. For a strict policy, install your own
// allow-list as a MechanismPolicyFunc.
func RejectWeakMechanisms(mechanism uint) error {
	if name, ok := weakMechanisms[mechanism]; ok {
		return fmt.Errorf("cryptoki: mechanism %#x (%s) is weak and rejected by policy", mechanism, name)
	}
	return nil
}
