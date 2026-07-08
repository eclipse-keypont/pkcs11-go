// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package p11

import "github.com/eclipse-keypont/pkcs11-go/cryptoki"

// SecretKey, PublicKey and PrivateKey are Objects specialised with the crypto
// operations appropriate to each. They share Object's identity fields, so an
// Object accessor is available on each via Object().
//
// Each method that performs an init→operation pair holds the owning Session's
// mutex for the whole pair, so two goroutines sharing a Session cannot corrupt
// each other's active operation.
type (
	// SecretKey is a symmetric key object.
	SecretKey Object
	// PublicKey is an asymmetric public key object.
	PublicKey Object
	// PrivateKey is an asymmetric private key object.
	PrivateKey Object
)

// KeyPair bundles the two halves returned by Session.GenerateKeyPair.
type KeyPair struct {
	Public  PublicKey
	Private PrivateKey
}

// Object returns the underlying Object (for Label, Attribute, Destroy, …).
func (k SecretKey) Object() Object { return Object(k) }

// Object returns the underlying Object (for Label, Attribute, Destroy, …).
func (k PublicKey) Object() Object { return Object(k) }

// Object returns the underlying Object (for Label, Attribute, Destroy, …).
func (k PrivateKey) Object() Object { return Object(k) }

// ── SecretKey ────────────────────────────────────────────────────────────────

// Encrypt encrypts plaintext under the secret key (C_EncryptInit + C_Encrypt).
func (k SecretKey) Encrypt(mechanism *cryptoki.Mechanism, plaintext []byte) ([]byte, error) {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	if err := k.session.ctx.EncryptInit(k.session.handle, mechanism, k.handle); err != nil {
		return nil, err
	}
	return k.session.ctx.Encrypt(k.session.handle, plaintext)
}

// Decrypt decrypts ciphertext under the secret key (C_DecryptInit + C_Decrypt).
func (k SecretKey) Decrypt(mechanism *cryptoki.Mechanism, ciphertext []byte) ([]byte, error) {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	if err := k.session.ctx.DecryptInit(k.session.handle, mechanism, k.handle); err != nil {
		return nil, err
	}
	return k.session.ctx.Decrypt(k.session.handle, ciphertext)
}

// Wrap wraps another key with this secret key (C_WrapKey).
func (k SecretKey) Wrap(mechanism *cryptoki.Mechanism, key Object) ([]byte, error) {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	return k.session.ctx.WrapKey(k.session.handle, mechanism, k.handle, key.handle)
}

// Unwrap unwraps a key with this secret key into a new object (C_UnwrapKey).
func (k SecretKey) Unwrap(mechanism *cryptoki.Mechanism, wrapped []byte, template []*cryptoki.Attribute) (Object, error) {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	h, err := k.session.ctx.UnwrapKey(k.session.handle, mechanism, k.handle, wrapped, template)
	if err != nil {
		return Object{}, err
	}
	return Object{session: k.session, handle: h}, nil
}

// ── PublicKey ────────────────────────────────────────────────────────────────

// Encrypt encrypts plaintext under the public key (C_EncryptInit + C_Encrypt).
func (k PublicKey) Encrypt(mechanism *cryptoki.Mechanism, plaintext []byte) ([]byte, error) {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	if err := k.session.ctx.EncryptInit(k.session.handle, mechanism, k.handle); err != nil {
		return nil, err
	}
	return k.session.ctx.Encrypt(k.session.handle, plaintext)
}

// Verify checks a signature over message with the public key (C_VerifyInit +
// C_Verify). A nil error means the signature is valid.
func (k PublicKey) Verify(mechanism *cryptoki.Mechanism, message, signature []byte) error {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	if err := k.session.ctx.VerifyInit(k.session.handle, mechanism, k.handle); err != nil {
		return err
	}
	return k.session.ctx.Verify(k.session.handle, message, signature)
}

// VerifyStateless checks a signature using the v3.2 stateless flow
// (C_VerifySignatureInit + C_VerifySignature).
func (k PublicKey) VerifyStateless(mechanism *cryptoki.Mechanism, message, signature []byte) error {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	if err := k.session.ctx.VerifySignatureInit(k.session.handle, mechanism, k.handle, signature); err != nil {
		return err
	}
	return k.session.ctx.VerifySignature(k.session.handle, message)
}

// Encapsulate runs a KEM encapsulation under the public key, returning the
// ciphertext and the freshly created shared-secret key (C_EncapsulateKey).
func (k PublicKey) Encapsulate(mechanism *cryptoki.Mechanism, derivedKeyTemplate []*cryptoki.Attribute) ([]byte, SecretKey, error) {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	ct, h, err := k.session.ctx.EncapsulateKey(k.session.handle, mechanism, k.handle, derivedKeyTemplate)
	if err != nil {
		return nil, SecretKey{}, err
	}
	return ct, SecretKey{session: k.session, handle: h}, nil
}

// ── PrivateKey ───────────────────────────────────────────────────────────────

// Sign signs message with the private key (C_SignInit + C_Sign).
func (k PrivateKey) Sign(mechanism *cryptoki.Mechanism, message []byte) ([]byte, error) {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	if err := k.session.ctx.SignInit(k.session.handle, mechanism, k.handle); err != nil {
		return nil, err
	}
	return k.session.ctx.Sign(k.session.handle, message)
}

// Decrypt decrypts ciphertext with the private key (C_DecryptInit + C_Decrypt).
func (k PrivateKey) Decrypt(mechanism *cryptoki.Mechanism, ciphertext []byte) ([]byte, error) {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	if err := k.session.ctx.DecryptInit(k.session.handle, mechanism, k.handle); err != nil {
		return nil, err
	}
	return k.session.ctx.Decrypt(k.session.handle, ciphertext)
}

// Derive derives a new key from this private key (C_DeriveKey), e.g. ECDH1.
func (k PrivateKey) Derive(mechanism *cryptoki.Mechanism, template []*cryptoki.Attribute) (SecretKey, error) {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	h, err := k.session.ctx.DeriveKey(k.session.handle, mechanism, k.handle, template)
	if err != nil {
		return SecretKey{}, err
	}
	return SecretKey{session: k.session, handle: h}, nil
}

// Decapsulate recovers the shared-secret key from ciphertext with the private
// key (C_DecapsulateKey).
func (k PrivateKey) Decapsulate(mechanism *cryptoki.Mechanism, ciphertext []byte, derivedKeyTemplate []*cryptoki.Attribute) (SecretKey, error) {
	k.session.mu.Lock()
	defer k.session.mu.Unlock()
	h, err := k.session.ctx.DecapsulateKey(k.session.handle, mechanism, k.handle, derivedKeyTemplate, ciphertext)
	if err != nil {
		return SecretKey{}, err
	}
	return SecretKey{session: k.session, handle: h}, nil
}
