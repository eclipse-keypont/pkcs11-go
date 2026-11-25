// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package p11

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestFindObjectsBounded checks that FindObjects stops, with an error, once
// more than maxFoundObjects objects have come back, against a module whose
// search never returns the empty batch that ends it.
func TestFindObjectsBounded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the mock module is built with a Unix-style toolchain")
	}
	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		t.Skipf("no C compiler to build the mock module: %v", err)
	}
	headers, err := filepath.Abs(filepath.Join("..", "internal", "headers"))
	if err != nil {
		t.Fatal(err)
	}
	lib := filepath.Join(t.TempDir(), "mock.so")
	// #nosec G204 -- the compiler and its arguments are fixed test inputs.
	cmd := exec.Command(cc, "-shared", "-fPIC", "-I", headers, "-o", lib,
		filepath.Join("testdata", "findmock", "mock.c"))
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building mock module: %v\n%s", err, b)
	}

	mod, err := OpenModule(lib)
	if err != nil {
		t.Fatalf("OpenModule: %v", err)
	}
	defer func() { _ = mod.Close() }()
	slots, err := mod.Slots()
	if err != nil || len(slots) != 1 {
		t.Fatalf("Slots = %v, %v, want one slot", slots, err)
	}
	sess, err := slots[0].OpenSession()
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer func() { _ = sess.Close() }()

	if objs, err := sess.FindObjects(nil); err == nil {
		t.Fatalf("FindObjects = %d objects, want an error past %d", len(objs), maxFoundObjects)
	}
}
