// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

/*
#include <stdlib.h>
#include "shim.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// SlotInfo describes a slot (CK_SLOT_INFO), as returned by GetSlotInfo.
type SlotInfo struct {
	SlotDescription string
	ManufacturerID  string
	Flags           uint
	HardwareVersion Version
	FirmwareVersion Version
}

// TokenInfo describes the token in a slot (CK_TOKEN_INFO), from GetTokenInfo.
type TokenInfo struct {
	Label              string
	ManufacturerID     string
	Model              string
	SerialNumber       string
	Flags              uint
	MaxSessionCount    uint
	SessionCount       uint
	MaxRwSessionCount  uint
	RwSessionCount     uint
	MaxPinLen          uint
	MinPinLen          uint
	TotalPublicMemory  uint
	FreePublicMemory   uint
	TotalPrivateMemory uint
	FreePrivateMemory  uint
	HardwareVersion    Version
	FirmwareVersion    Version
	UTCTime            string
}

// MechanismInfo describes a mechanism's capabilities (CK_MECHANISM_INFO).
type MechanismInfo struct {
	MinKeySize uint
	MaxKeySize uint
	Flags      uint
}

// GetSlotList returns the slot IDs in the system (C_GetSlotList). When
// tokenPresent is true, only slots with a token present are returned.
func (c *Ctx) GetSlotList(tokenPresent bool) ([]SlotID, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()

	present := C.CK_BBOOL(C.CK_FALSE)
	if tokenPresent {
		present = C.CK_BBOOL(C.CK_TRUE)
	}

	var count C.CK_ULONG
	if err := toError(uint(C.ck_get_slot_list(m, present, nil, &count))); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	list := make([]C.CK_SLOT_ID, count)
	if err := toError(uint(C.ck_get_slot_list(m, present, &list[0], &count))); err != nil {
		return nil, err
	}

	out := make([]SlotID, count)
	for i := range out {
		out[i] = SlotID(list[i])
	}
	return out, nil
}

// GetSlotInfo returns information about a slot (C_GetSlotInfo).
func (c *Ctx) GetSlotInfo(slot SlotID) (SlotInfo, error) {
	m, release, err := c.grab()
	if err != nil {
		return SlotInfo{}, err
	}
	defer release()
	var info C.CK_SLOT_INFO
	if err := toError(uint(C.ck_get_slot_info(m, C.CK_SLOT_ID(slot), &info))); err != nil {
		return SlotInfo{}, err
	}
	return SlotInfo{
		SlotDescription: goPaddedString(unsafe.Pointer(&info.slotDescription[0]), len(info.slotDescription)),
		ManufacturerID:  goPaddedString(unsafe.Pointer(&info.manufacturerID[0]), len(info.manufacturerID)),
		Flags:           uint(info.flags),
		HardwareVersion: goVersion(info.hardwareVersion),
		FirmwareVersion: goVersion(info.firmwareVersion),
	}, nil
}

// GetTokenInfo returns information about the token in a slot (C_GetTokenInfo).
func (c *Ctx) GetTokenInfo(slot SlotID) (TokenInfo, error) {
	m, release, err := c.grab()
	if err != nil {
		return TokenInfo{}, err
	}
	defer release()
	var info C.CK_TOKEN_INFO
	if err := toError(uint(C.ck_get_token_info(m, C.CK_SLOT_ID(slot), &info))); err != nil {
		return TokenInfo{}, err
	}
	return TokenInfo{
		Label:              goPaddedString(unsafe.Pointer(&info.label[0]), len(info.label)),
		ManufacturerID:     goPaddedString(unsafe.Pointer(&info.manufacturerID[0]), len(info.manufacturerID)),
		Model:              goPaddedString(unsafe.Pointer(&info.model[0]), len(info.model)),
		SerialNumber:       goPaddedString(unsafe.Pointer(&info.serialNumber[0]), len(info.serialNumber)),
		Flags:              uint(info.flags),
		MaxSessionCount:    uint(info.ulMaxSessionCount),
		SessionCount:       uint(info.ulSessionCount),
		MaxRwSessionCount:  uint(info.ulMaxRwSessionCount),
		RwSessionCount:     uint(info.ulRwSessionCount),
		MaxPinLen:          uint(info.ulMaxPinLen),
		MinPinLen:          uint(info.ulMinPinLen),
		TotalPublicMemory:  uint(info.ulTotalPublicMemory),
		FreePublicMemory:   uint(info.ulFreePublicMemory),
		TotalPrivateMemory: uint(info.ulTotalPrivateMemory),
		FreePrivateMemory:  uint(info.ulFreePrivateMemory),
		HardwareVersion:    goVersion(info.hardwareVersion),
		FirmwareVersion:    goVersion(info.firmwareVersion),
		UTCTime:            goPaddedString(unsafe.Pointer(&info.utcTime[0]), len(info.utcTime)),
	}, nil
}

// GetMechanismList returns the mechanism types a slot supports
// (C_GetMechanismList).
func (c *Ctx) GetMechanismList(slot SlotID) ([]uint, error) {
	m, release, err := c.grab()
	if err != nil {
		return nil, err
	}
	defer release()

	var count C.CK_ULONG
	if err := toError(uint(C.ck_get_mechanism_list(m, C.CK_SLOT_ID(slot), nil, &count))); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}

	list := make([]C.CK_MECHANISM_TYPE, count)
	if err := toError(uint(C.ck_get_mechanism_list(m, C.CK_SLOT_ID(slot), &list[0], &count))); err != nil {
		return nil, err
	}

	out := make([]uint, count)
	for i := range out {
		out[i] = uint(list[i])
	}
	return out, nil
}

// GetMechanismInfo returns the capabilities of one mechanism on a slot
// (C_GetMechanismInfo).
func (c *Ctx) GetMechanismInfo(slot SlotID, mechanism uint) (MechanismInfo, error) {
	m, release, err := c.grab()
	if err != nil {
		return MechanismInfo{}, err
	}
	defer release()
	var info C.CK_MECHANISM_INFO
	rv := C.ck_get_mechanism_info(m, C.CK_SLOT_ID(slot), C.CK_MECHANISM_TYPE(mechanism), &info)
	if err := toError(uint(rv)); err != nil {
		return MechanismInfo{}, err
	}
	return MechanismInfo{
		MinKeySize: uint(info.ulMinKeySize),
		MaxKeySize: uint(info.ulMaxKeySize),
		Flags:      uint(info.flags),
	}, nil
}

// InitToken initialises the token in a slot with the given security-officer PIN
// and label (C_InitToken). The label is space-padded to 32 bytes per the spec;
// a label longer than 32 bytes is rejected rather than truncated (truncation
// could split a multi-byte UTF-8 rune and yield an invalid CK_UTF8CHAR field).
// The PIN is taken as []byte and the C copy is scrubbed before being freed.
func (c *Ctx) InitToken(slot SlotID, soPin []byte, label string) error {
	if len([]byte(label)) > 32 {
		return fmt.Errorf("cryptoki: token label must be at most 32 bytes, got %d", len([]byte(label)))
	}
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	pin, pinLen := cBytes(soPin)
	defer zfree(pin, pinLen)

	// C_InitToken expects a 32-byte, space-padded label.
	padded := make([]byte, 32)
	for i := range padded {
		padded[i] = ' '
	}
	copy(padded, label)
	clabel := C.CBytes(padded)
	defer C.free(clabel)

	rv := C.ck_init_token(m, C.CK_SLOT_ID(slot),
		(C.CK_UTF8CHAR_PTR)(pin), pinLen, (C.CK_UTF8CHAR_PTR)(clabel))
	return toError(uint(rv))
}

// InitPIN sets the normal user's PIN from a security-officer session
// (C_InitPIN). The C copy of the PIN is scrubbed before being freed.
func (c *Ctx) InitPIN(sh SessionHandle, pin []byte) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	p, n := cBytes(pin)
	defer zfree(p, n)
	rv := C.ck_init_pin(m, C.CK_SESSION_HANDLE(sh), (C.CK_UTF8CHAR_PTR)(p), n)
	return toError(uint(rv))
}

// SetPIN changes the PIN of the logged-in user (C_SetPIN). Both C copies are
// scrubbed before being freed.
func (c *Ctx) SetPIN(sh SessionHandle, oldPin, newPin []byte) error {
	m, release, err := c.grab()
	if err != nil {
		return err
	}
	defer release()
	op, oln := cBytes(oldPin)
	defer zfree(op, oln)
	np, nln := cBytes(newPin)
	defer zfree(np, nln)
	rv := C.ck_set_pin(m, C.CK_SESSION_HANDLE(sh),
		(C.CK_UTF8CHAR_PTR)(op), oln, (C.CK_UTF8CHAR_PTR)(np), nln)
	return toError(uint(rv))
}

// WaitForSlotEvent blocks until a slot event (token insertion or removal)
// occurs, then returns the affected slot ID (C_WaitForSlotEvent). Pass
// CKF_DONT_BLOCK (= 1) to return immediately: when no event is pending the
// error will be CKR_NO_EVENT (= 0x00000008).
func (c *Ctx) WaitForSlotEvent(flags uint) (SlotID, error) {
	m, release, err := c.grab()
	if err != nil {
		return 0, err
	}
	defer release()
	var slot C.CK_SLOT_ID
	rv := C.ck_wait_for_slot_event(m, C.CK_FLAGS(flags), &slot)
	if err := toError(uint(rv)); err != nil {
		return 0, err
	}
	return SlotID(slot), nil
}

// free is C.free guarded against nil, for use with deferred cleanups.
func free(p unsafe.Pointer) {
	if p != nil {
		C.free(p)
	}
}
