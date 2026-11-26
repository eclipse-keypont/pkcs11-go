// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// compileTestModule compiles the C source src (relative to this package) into
// a shared object, with the given preprocessor defines, and returns its
// absolute path. It skips the test where no C compiler is available.
func compileTestModule(t *testing.T, src string, defines ...string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the test module is built with a Unix-style toolchain")
	}
	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		t.Skipf("no C compiler to build the test module: %v", err)
	}
	headers, err := filepath.Abs(filepath.Join("..", "internal", "headers"))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "module.so")
	// #nosec G204 -- the compiler and its arguments are fixed test inputs.
	args := []string{"-shared", "-fPIC", "-I", headers, "-o", out}
	for _, d := range defines {
		args = append(args, "-D"+d)
	}
	cmd := exec.Command(cc, append(args, src, "-lpthread")...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building test module: %v\n%s", err, b)
	}
	return out
}

// TestFinalizeWakesBlockingWait checks that Finalize, the specification's way
// to wake a blocking C_WaitForSlotEvent, is not itself held up by that wait,
// and that Destroy then completes.
func TestFinalizeWakesBlockingWait(t *testing.T) {
	ctx, err := New(compileTestModule(t, filepath.Join("testdata", "waitmock", "mock.c")))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := ctx.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	waited := make(chan error, 1)
	go func() {
		_, err := ctx.WaitForSlotEvent(0)
		waited <- err
	}()

	// The mock lists a slot only while a wait is parked in it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		slots, err := ctx.GetSlotList(false)
		if err != nil {
			t.Fatalf("GetSlotList: %v", err)
		}
		if len(slots) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("WaitForSlotEvent never blocked in the module")
		}
		time.Sleep(time.Millisecond)
	}

	finalized := make(chan error, 1)
	go func() { finalized <- ctx.Finalize() }()
	select {
	case err := <-finalized:
		if err != nil {
			t.Fatalf("Finalize: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Finalize did not return while WaitForSlotEvent was blocked")
	}

	select {
	case err := <-waited:
		if !errors.Is(err, Error(CKR_CRYPTOKI_NOT_INITIALIZED)) {
			t.Fatalf("WaitForSlotEvent = %v, want CKR_CRYPTOKI_NOT_INITIALIZED", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitForSlotEvent did not return after Finalize")
	}

	destroyed := make(chan struct{})
	go func() {
		ctx.Destroy()
		close(destroyed)
	}()
	select {
	case <-destroyed:
	case <-time.After(5 * time.Second):
		t.Fatal("Destroy did not return")
	}
}
