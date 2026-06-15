// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package p11

import (
	"sync"

	"github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// Module is a loaded and initialised PKCS #11 module. It owns the underlying
// cryptoki.Ctx; release it with Close.
type Module struct {
	ctx       *cryptoki.Ctx
	closeOnce sync.Once
	closeErr  error
}

// OpenModule loads the PKCS #11 module at path (which must be absolute) and
// calls C_Initialize. Release it with Close (which finalises and unloads).
func OpenModule(path string) (*Module, error) {
	ctx, err := cryptoki.New(path)
	if err != nil {
		return nil, err
	}
	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		return nil, err
	}
	return &Module{ctx: ctx}, nil
}

// Info returns general information about the library (C_GetInfo).
func (m *Module) Info() (cryptoki.Info, error) {
	return m.ctx.GetInfo()
}

// SupportsV32 reports whether the module exposes the PKCS #11 v3.2 interface.
func (m *Module) SupportsV32() bool {
	return m.ctx.SupportsV32()
}

// Slots returns the slots that currently have a token present.
func (m *Module) Slots() ([]Slot, error) {
	return m.slots(true)
}

// AllSlots returns every slot, including those without a token (useful for
// initialising a fresh token with Slot.InitToken).
func (m *Module) AllSlots() ([]Slot, error) {
	return m.slots(false)
}

func (m *Module) slots(tokenPresent bool) ([]Slot, error) {
	ids, err := m.ctx.GetSlotList(tokenPresent)
	if err != nil {
		return nil, err
	}
	out := make([]Slot, len(ids))
	for i, id := range ids {
		out[i] = Slot{ctx: m.ctx, id: id}
	}
	return out, nil
}

// Close finalises the module (C_Finalize) and unloads the library. It is
// idempotent: only the first call runs C_Finalize and Destroy, and every call
// returns that first call's error. Close must not race with in-flight calls on
// the same module.
func (m *Module) Close() error {
	m.closeOnce.Do(func() {
		m.closeErr = m.ctx.Finalize()
		m.ctx.Destroy()
	})
	return m.closeErr
}
