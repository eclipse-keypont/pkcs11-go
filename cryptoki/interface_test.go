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
)

// buildMockModule compiles testdata/ifacemock/mock.c into a shared object
// with the given preprocessor defines and returns its absolute path. It skips
// the test where no C compiler is available.
func buildMockModule(t *testing.T, defines ...string) string {
	t.Helper()
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
	out := filepath.Join(t.TempDir(), "mock.so")
	args := []string{"-shared", "-fPIC", "-I", headers, "-o", out}
	for _, d := range defines {
		args = append(args, "-D"+d)
	}
	args = append(args, filepath.Join("testdata", "ifacemock", "mock.c"))
	// #nosec G204 -- the compiler and its arguments are fixed test inputs.
	if b, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
		t.Fatalf("building mock module: %v\n%s", err, b)
	}
	return out
}

// TestInterfaceNegotiation checks that the binding finds a module's PKCS #11
// 3.2 interface whether or not it is the module's default.
func TestInterfaceNegotiation(t *testing.T) {
	cases := []struct {
		name    string
		defines []string
		wantV32 bool
	}{
		// The default interface is 3.0; 3.2 has to be asked for by version.
		{"Default30Offers32", nil, true},
		// The module refuses version lookups; its default interface is 3.2.
		{"Default32", []string{"MOCK_DEFAULT_32"}, true},
		{"Only30", []string{"MOCK_ONLY_30"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, err := New(buildMockModule(t, c.defines...))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer ctx.Destroy()
			if got := ctx.SupportsV32(); got != c.wantV32 {
				t.Fatalf("SupportsV32() = %v, want %v", got, c.wantV32)
			}
		})
	}
}

// TestNullFunctionPointer checks that a function-list entry the module left
// NULL is reported as CKR_FUNCTION_NOT_SUPPORTED rather than called. Every
// entry of the mock's function lists is NULL.
func TestNullFunctionPointer(t *testing.T) {
	ctx, err := New(buildMockModule(t, "MOCK_DEFAULT_32"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ctx.Destroy()

	notSupported := Error(CKR_FUNCTION_NOT_SUPPORTED)
	if err := ctx.Initialize(); !errors.Is(err, notSupported) {
		t.Errorf("Initialize = %v, want CKR_FUNCTION_NOT_SUPPORTED", err)
	}
	if _, err := ctx.GetInfo(); !errors.Is(err, notSupported) {
		t.Errorf("GetInfo = %v, want CKR_FUNCTION_NOT_SUPPORTED", err)
	}
	if _, err := ctx.GetSlotList(false); !errors.Is(err, notSupported) {
		t.Errorf("GetSlotList = %v, want CKR_FUNCTION_NOT_SUPPORTED", err)
	}
	if err := ctx.SessionCancel(1, CKF_ENCRYPT); !errors.Is(err, notSupported) {
		t.Errorf("SessionCancel = %v, want CKR_FUNCTION_NOT_SUPPORTED", err)
	}
}
