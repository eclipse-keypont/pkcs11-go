// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

// Package p11 is an ergonomic, object-oriented layer over the low-level
// cryptoki binding. Instead of threading a *cryptoki.Ctx and raw handles
// through every call, it exposes Module, Slot, Session, Object and typed key
// values whose methods carry the context for you:
//
//	mod, err := p11.OpenModule("/usr/lib/softhsm/libsofthsm2.so")
//	...
//	defer mod.Close()
//	slots, _ := mod.Slots()
//	session, _ := slots[0].OpenWriteSession()
//	defer session.Close()
//	pin := []byte("1234")
//	_ = session.Login(pin)
//	cryptoki.Wipe(pin)
//	key, _ := session.FindSecretKey("my-aes-key")
//	ct, _ := key.Encrypt(cryptoki.NewMechanism(cryptoki.CKM_AES_CBC_PAD, iv), plaintext)
//
// Mechanisms and attributes are still the cryptoki types
// (cryptoki.Mechanism, cryptoki.Attribute), built with cryptoki.NewMechanism /
// cryptoki.NewAttribute, so the full low-level vocabulary remains available.
package p11
