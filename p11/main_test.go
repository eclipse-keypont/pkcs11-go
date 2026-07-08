// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package p11

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

// These tests exercise the high-level p11 layer against a real module when
// PKCS11_MODULE is set (SoftHSMv3 recommended); otherwise they skip. The token
// is bootstrapped through p11 itself, dogfooding Slot.InitToken / Session.InitPIN.

const (
	testLabel = "p11-test"
)

var (
	testModule string
	testMod    *Module
	testSlot   Slot
	testTmpDir string
	testReady  bool
)

var testSOPin = []byte("0000")

func testUserPin() []byte {
	if p := os.Getenv("PKCS11_PIN"); p != "" {
		return []byte(p)
	}
	return []byte("1234")
}

func TestMain(m *testing.M) {
	testModule = os.Getenv("PKCS11_MODULE")
	if testModule != "" {
		if abs, err := filepath.Abs(testModule); err == nil {
			testModule = abs
		}
		if err := setup(); err != nil {
			fmt.Fprintln(os.Stderr, "p11 integration setup failed:", err)
			os.Exit(1)
		}
		testReady = true
	}
	code := m.Run()
	if testMod != nil {
		_ = testMod.Close()
	}
	if testTmpDir != "" {
		_ = os.RemoveAll(testTmpDir)
	}
	os.Exit(code)
}

// setup bootstraps an ephemeral token and leaves testMod open with testSlot
// pointing at it. A single module load is used throughout, so the slot ID is
// stable.
func setup() error {
	dir, err := os.MkdirTemp("", "p11-softhsm-*")
	if err != nil {
		return err
	}
	testTmpDir = dir
	tokens := filepath.Join(dir, "tokens")
	if err := os.Mkdir(tokens, 0o700); err != nil {
		return err
	}
	conf := filepath.Join(dir, "softhsm2.conf")
	body := fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n", tokens)
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		return err
	}
	if err := os.Setenv("SOFTHSM2_CONF", conf); err != nil {
		return err
	}

	mod, err := OpenModule(testModule)
	if err != nil {
		return err
	}
	testMod = mod

	all, err := mod.AllSlots()
	if err != nil || len(all) == 0 {
		return fmt.Errorf("AllSlots: %v (count=%d)", err, len(all))
	}
	if err := all[0].InitToken(testSOPin, testLabel); err != nil {
		return fmt.Errorf("InitToken: %w", err)
	}

	slot, err := slotByLabel(mod, testLabel)
	if err != nil {
		return err
	}
	testSlot = slot

	sess, err := slot.OpenWriteSession()
	if err != nil {
		return fmt.Errorf("OpenWriteSession: %w", err)
	}
	defer func() { _ = sess.Close() }()
	if err := sess.LoginSecurityOfficer(testSOPin); err != nil {
		return fmt.Errorf("Login(SO): %w", err)
	}
	defer func() { _ = sess.Logout() }()
	if err := sess.InitPIN(testUserPin()); err != nil {
		return fmt.Errorf("InitPIN: %w", err)
	}
	return nil
}

func slotByLabel(mod *Module, label string) (Slot, error) {
	all, err := mod.AllSlots()
	if err != nil {
		return Slot{}, err
	}
	for _, s := range all {
		ti, err := s.TokenInfo()
		if err != nil {
			continue
		}
		if ti.Label == label {
			return s, nil
		}
	}
	return Slot{}, fmt.Errorf("no token with label %q", label)
}

// requireSession returns a logged-in R/W session, skipping when integration is
// disabled. The session is closed at test end.
func requireSession(t *testing.T) *Session {
	t.Helper()
	if !testReady {
		t.Skip("set PKCS11_MODULE to run p11 integration tests")
	}
	sess, err := testSlot.OpenWriteSession()
	if err != nil {
		t.Fatalf("OpenWriteSession: %v", err)
	}
	if err := sess.Login(testUserPin()); err != nil {
		_ = sess.Close()
		t.Fatalf("Login: %v", err)
	}
	t.Cleanup(func() {
		_ = sess.Logout()
		_ = sess.Close()
	})
	return sess
}

// hasMech reports whether the test token supports a mechanism.
func hasMech(t *testing.T, mech uint) bool {
	t.Helper()
	ms, err := testSlot.Mechanisms()
	if err != nil {
		t.Fatalf("Mechanisms: %v", err)
	}
	for _, m := range ms {
		if m.Type() == mech {
			return true
		}
	}
	return false
}

// aesKeyTemplate is a session AES-256 key usable for encrypt/decrypt.
func aesKeyTemplate(label string) []*cryptoki.Attribute {
	return []*cryptoki.Attribute{
		cryptoki.NewAttribute(cryptoki.CKA_CLASS, uint(cryptoki.CKO_SECRET_KEY)),
		cryptoki.NewAttribute(cryptoki.CKA_KEY_TYPE, uint(cryptoki.CKK_AES)),
		cryptoki.NewAttribute(cryptoki.CKA_VALUE_LEN, 32),
		cryptoki.NewAttribute(cryptoki.CKA_TOKEN, false),
		cryptoki.NewAttribute(cryptoki.CKA_LABEL, label),
		cryptoki.NewAttribute(cryptoki.CKA_ENCRYPT, true),
		cryptoki.NewAttribute(cryptoki.CKA_DECRYPT, true),
	}
}
