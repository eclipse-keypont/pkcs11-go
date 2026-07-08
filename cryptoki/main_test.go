// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Integration tests run only when PKCS11_MODULE points at a PKCS #11 module.
// SoftHSMv3 (github.com/pqctoday/pqctoday-hsm) is recommended; a v2 libsofthsm2
// also works for the v2.x suite. The token is bootstrapped entirely through the
// Cryptoki API in a throwaway directory — no softhsm2-util needed.
//
// When PKCS11_MODULE is unset, the unit tests still run and the integration
// tests skip themselves via requireSession.

const (
	testLabel = "ckgo-test"
)

var (
	testModule string // value of PKCS11_MODULE, "" disables integration tests
	testCtx    *Ctx   // shared, initialised module for the integration tests
	testSlot   SlotID // slot holding the bootstrapped token
	testTmpDir string // throwaway SoftHSM token store, removed on exit
	testReady  bool   // true once the token and shared Ctx are ready
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
		if err := setupToken(); err != nil {
			fmt.Fprintln(os.Stderr, "integration setup failed:", err)
			os.Exit(1)
		}
		ctx, err := New(testModule)
		if err == nil {
			err = ctx.Initialize()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "integration setup failed to open module:", err)
			os.Exit(1)
		}
		// Resolve the slot against this (shared) module load: SoftHSM can number
		// slots differently between loads, so the value from setup is not reused.
		slot, err := slotForLabel(ctx, testLabel)
		if err != nil {
			fmt.Fprintln(os.Stderr, "integration setup failed to locate token:", err)
			os.Exit(1)
		}
		testCtx = ctx
		testSlot = slot
		testReady = true
	}

	code := m.Run()

	if testCtx != nil {
		_ = testCtx.Finalize()
		testCtx.Destroy()
	}
	if testTmpDir != "" {
		_ = os.RemoveAll(testTmpDir)
	}
	os.Exit(code)
}

// setupToken creates an ephemeral SoftHSM config and initialises a fresh token
// with a known SO-PIN, user-PIN and label, recording its slot in testSlot.
//
// The flow is pure PKCS #11:
//  1. Initialize, GetSlotList(false) → an uninitialised slot
//  2. InitToken(SO-PIN, label)
//  3. GetSlotList(true) and match our label → the token's new slot
//  4. OpenSession(RW), Login(SO), InitPIN(user-PIN)
func setupToken() error {
	dir, err := os.MkdirTemp("", "ckgo-softhsm-*")
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
	// Must be set before the module reads its configuration.
	if err := os.Setenv("SOFTHSM2_CONF", conf); err != nil {
		return err
	}

	ctx, err := New(testModule)
	if err != nil {
		return err
	}
	defer ctx.Destroy()
	if err := ctx.Initialize(); err != nil {
		return fmt.Errorf("Initialize: %w", err)
	}
	defer func() { _ = ctx.Finalize() }()

	free, err := ctx.GetSlotList(false)
	if err != nil {
		return fmt.Errorf("GetSlotList(false): %w", err)
	}
	if len(free) == 0 {
		return fmt.Errorf("no slots reported by module")
	}
	if err := ctx.InitToken(free[0], testSOPin, testLabel); err != nil {
		return fmt.Errorf("InitToken: %w", err)
	}

	slot, err := slotForLabel(ctx, testLabel)
	if err != nil {
		return err
	}

	sh, err := ctx.OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("OpenSession: %w", err)
	}
	defer func() { _ = ctx.CloseSession(sh) }()
	if err := ctx.Login(sh, CKU_SO, testSOPin); err != nil {
		return fmt.Errorf("Login(SO): %w", err)
	}
	defer func() { _ = ctx.Logout(sh) }()
	if err := ctx.InitPIN(sh, testUserPin()); err != nil {
		return fmt.Errorf("InitPIN: %w", err)
	}
	return nil
}

// slotForLabel returns the slot whose token has the given label.
func slotForLabel(ctx *Ctx, label string) (SlotID, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("GetSlotList(true): %w", err)
	}
	for _, s := range slots {
		ti, err := ctx.GetTokenInfo(s)
		if err != nil {
			return 0, fmt.Errorf("GetTokenInfo(%d): %w", s, err)
		}
		if ti.Label == label {
			return s, nil
		}
	}
	return 0, fmt.Errorf("no token with label %q found", label)
}

// requireSession skips the calling test when integration is disabled, otherwise
// returns a fresh user-authenticated R/W session that is closed at test end.
func requireSession(t *testing.T) SessionHandle {
	t.Helper()
	if !testReady {
		t.Skip("set PKCS11_MODULE to run integration tests")
	}
	sh, err := testCtx.OpenSession(testSlot, CKF_SERIAL_SESSION|CKF_RW_SESSION)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if err := testCtx.Login(sh, CKU_USER, testUserPin()); err != nil {
		_ = testCtx.CloseSession(sh)
		t.Fatalf("Login(USER): %v", err)
	}
	t.Cleanup(func() {
		_ = testCtx.Logout(sh)
		_ = testCtx.CloseSession(sh)
	})
	return sh
}
