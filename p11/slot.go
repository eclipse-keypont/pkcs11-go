// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package p11

import "github.com/eclipse-keypont/pkcs11-go/cryptoki"

// Slot is a slot in a loaded module.
type Slot struct {
	ctx *cryptoki.Ctx
	id  cryptoki.SlotID
}

// ID returns the slot identifier.
func (s Slot) ID() uint { return uint(s.id) }

// Info returns information about the slot (C_GetSlotInfo).
func (s Slot) Info() (cryptoki.SlotInfo, error) {
	return s.ctx.GetSlotInfo(s.id)
}

// TokenInfo returns information about the token in the slot (C_GetTokenInfo).
func (s Slot) TokenInfo() (cryptoki.TokenInfo, error) {
	return s.ctx.GetTokenInfo(s.id)
}

// InitToken initialises the token with a security-officer PIN and label
// (C_InitToken). The PIN is taken as []byte so it can be wiped after use.
func (s Slot) InitToken(securityOfficerPIN []byte, label string) error {
	return s.ctx.InitToken(s.id, securityOfficerPIN, label)
}

// Mechanisms returns the mechanisms supported by the slot.
func (s Slot) Mechanisms() ([]Mechanism, error) {
	types, err := s.ctx.GetMechanismList(s.id)
	if err != nil {
		return nil, err
	}
	out := make([]Mechanism, len(types))
	for i, t := range types {
		out[i] = Mechanism{ctx: s.ctx, slot: s.id, typ: t}
	}
	return out, nil
}

// OpenSession opens a read-only serial session on the slot's token.
func (s Slot) OpenSession() (*Session, error) {
	return s.OpenSessionWithFlags(cryptoki.CKF_SERIAL_SESSION)
}

// OpenWriteSession opens a read/write serial session on the slot's token.
func (s Slot) OpenWriteSession() (*Session, error) {
	return s.OpenSessionWithFlags(cryptoki.CKF_SERIAL_SESSION | cryptoki.CKF_RW_SESSION)
}

// OpenSessionWithFlags opens a session with explicit flags (C_OpenSession).
func (s Slot) OpenSessionWithFlags(flags uint) (*Session, error) {
	sh, err := s.ctx.OpenSession(s.id, flags)
	if err != nil {
		return nil, err
	}
	return &Session{ctx: s.ctx, handle: sh}, nil
}

// CloseAllSessions closes every session open on the slot's token
// (C_CloseAllSessions).
func (s Slot) CloseAllSessions() error {
	return s.ctx.CloseAllSessions(s.id)
}

// Mechanism is a mechanism type supported by a slot, with lazy access to its
// capability info.
type Mechanism struct {
	ctx  *cryptoki.Ctx
	slot cryptoki.SlotID
	typ  uint
}

// Type returns the CKM_ mechanism identifier.
func (m Mechanism) Type() uint { return m.typ }

// Info returns the mechanism's capabilities on its slot (C_GetMechanismInfo).
func (m Mechanism) Info() (cryptoki.MechanismInfo, error) {
	return m.ctx.GetMechanismInfo(m.slot, m.typ)
}
