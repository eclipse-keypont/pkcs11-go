// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package p11

import (
	"fmt"
	"sync"

	"github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// Session is an open session on a token. It is the entry point for finding,
// creating and generating objects, and for login.
//
// A PKCS #11 session is a single state machine: an init→…→final operation
// sequence (e.g. EncryptInit then Encrypt) must not interleave with another
// operation on the same session, even when the module was initialised with OS
// locking. Session guards each compound operation it performs with mu, so the
// convenience methods on SecretKey/PublicKey/PrivateKey are safe to call from
// multiple goroutines that share one Session. If you drop down to the raw
// cryptoki.Ctx via Handle(), you take over that responsibility.
type Session struct {
	ctx    *cryptoki.Ctx
	handle cryptoki.SessionHandle
	mu     sync.Mutex
}

// Handle returns the underlying cryptoki session handle, for dropping down to
// the low-level API when needed. Operations issued through the handle bypass
// the Session mutex; serialise them yourself.
func (s *Session) Handle() cryptoki.SessionHandle { return s.handle }

// Info returns information about the session (C_GetSessionInfo).
func (s *Session) Info() (cryptoki.SessionInfo, error) {
	return s.ctx.GetSessionInfo(s.handle)
}

// Login logs in as the normal user (CKU_USER). The PIN is taken as []byte so it
// can be wiped after use (cryptoki.Wipe).
func (s *Session) Login(pin []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx.Login(s.handle, cryptoki.CKU_USER, pin)
}

// LoginSecurityOfficer logs in as the security officer (CKU_SO).
func (s *Session) LoginSecurityOfficer(pin []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx.Login(s.handle, cryptoki.CKU_SO, pin)
}

// LoginAs logs in with an explicit user type.
func (s *Session) LoginAs(userType uint, pin []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx.Login(s.handle, userType, pin)
}

// Logout logs the current user out (C_Logout).
func (s *Session) Logout() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx.Logout(s.handle)
}

// InitPIN sets the normal user's PIN from a security-officer session
// (C_InitPIN).
func (s *Session) InitPIN(pin []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx.InitPIN(s.handle, pin)
}

// SetPIN changes the logged-in user's PIN (C_SetPIN).
func (s *Session) SetPIN(oldPIN, newPIN []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx.SetPIN(s.handle, oldPIN, newPIN)
}

// GenerateRandom returns length random bytes from the token (C_GenerateRandom).
func (s *Session) GenerateRandom(length int) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx.GenerateRandom(s.handle, length)
}

// Close closes the session (C_CloseSession).
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx.CloseSession(s.handle)
}

// CreateObject creates an object from a template (C_CreateObject).
func (s *Session) CreateObject(template []*cryptoki.Attribute) (Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.ctx.CreateObject(s.handle, template)
	if err != nil {
		return Object{}, err
	}
	return Object{session: s, handle: h}, nil
}

// GenerateKey generates a secret key (C_GenerateKey).
func (s *Session) GenerateKey(mechanism *cryptoki.Mechanism, template []*cryptoki.Attribute) (SecretKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, err := s.ctx.GenerateKey(s.handle, mechanism, template)
	if err != nil {
		return SecretKey{}, err
	}
	return SecretKey{session: s, handle: h}, nil
}

// GenerateKeyPair generates a public/private key pair (C_GenerateKeyPair).
func (s *Session) GenerateKeyPair(mechanism *cryptoki.Mechanism, publicTemplate, privateTemplate []*cryptoki.Attribute) (KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pub, priv, err := s.ctx.GenerateKeyPair(s.handle, mechanism, publicTemplate, privateTemplate)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		Public:  PublicKey{session: s, handle: pub},
		Private: PrivateKey{session: s, handle: priv},
	}, nil
}

// FindObjects returns every object matching the template. An empty template
// matches all objects in the session's view. The whole find sequence
// (Init→Find…→Final) is held under the session mutex so it cannot interleave
// with another operation.
func (s *Session) FindObjects(template []*cryptoki.Attribute) ([]Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ctx.FindObjectsInit(s.handle, template); err != nil {
		return nil, err
	}
	var found []Object
	for {
		batch, err := s.ctx.FindObjects(s.handle, 32)
		if err != nil {
			_ = s.ctx.FindObjectsFinal(s.handle)
			return nil, err
		}
		if len(batch) == 0 {
			break
		}
		for _, h := range batch {
			found = append(found, Object{session: s, handle: h})
		}
	}
	if err := s.ctx.FindObjectsFinal(s.handle); err != nil {
		return found, err
	}
	return found, nil
}

// FindObject returns the single object matching the template, erroring if none
// or more than one match.
func (s *Session) FindObject(template []*cryptoki.Attribute) (Object, error) {
	objs, err := s.FindObjects(template)
	if err != nil {
		return Object{}, err
	}
	switch len(objs) {
	case 0:
		return Object{}, fmt.Errorf("p11: no object matched the template")
	case 1:
		return objs[0], nil
	default:
		return Object{}, fmt.Errorf("p11: %d objects matched the template, expected one", len(objs))
	}
}

// FindSecretKey returns the unique secret key with the given label.
func (s *Session) FindSecretKey(label string) (SecretKey, error) {
	o, err := s.findByClassAndLabel(cryptoki.CKO_SECRET_KEY, label)
	return SecretKey(o), err
}

// FindPublicKey returns the unique public key with the given label.
func (s *Session) FindPublicKey(label string) (PublicKey, error) {
	o, err := s.findByClassAndLabel(cryptoki.CKO_PUBLIC_KEY, label)
	return PublicKey(o), err
}

// FindPrivateKey returns the unique private key with the given label.
func (s *Session) FindPrivateKey(label string) (PrivateKey, error) {
	o, err := s.findByClassAndLabel(cryptoki.CKO_PRIVATE_KEY, label)
	return PrivateKey(o), err
}

func (s *Session) findByClassAndLabel(class uint, label string) (Object, error) {
	return s.FindObject([]*cryptoki.Attribute{
		cryptoki.NewAttribute(cryptoki.CKA_CLASS, class),
		cryptoki.NewAttribute(cryptoki.CKA_LABEL, label),
	})
}
