// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateValueAcceptsRealForms checks the value grammar admits the shapes
// that actually occur in pkcs11t.h.
func TestValidateValueAcceptsRealForms(t *testing.T) {
	ok := []string{
		"0x00000000",
		"1",
		"true",
		"false",
		"^uint(0)",
		"(CKF_ARRAY_ATTRIBUTE | 0x211)",
		"CKM_VENDOR_DEFINED",
		"(0x80000000 | 0x00000001)",
		"0x0000000000000001",
	}
	for _, v := range ok {
		if err := validateValue("CK_TEST", v); err != nil {
			t.Errorf("validateValue(%q) = %v, want nil", v, err)
		}
	}
}

// TestValidateValueRejectsInjection checks that values which could break out of
// the generated const block are refused (M-P1).
func TestValidateValueRejectsInjection(t *testing.T) {
	bad := []string{
		"",                // empty
		"1; var x = 1",    // statement separator
		"1 // comment",    // line comment
		"1 /* comment */", // block comment
		`"string"`,        // string literal
		"1\n2",            // newline
		"foo()",           // call
		"1 `raw`",         // raw string
		"1 \\ 2",          // backslash
		"1 {2}",           // braces
		"1 'c'",           // rune literal
	}
	for _, v := range bad {
		if err := validateValue("CK_TEST", v); err == nil {
			t.Errorf("validateValue(%q) = nil, want error", v)
		}
	}
}

// TestParseRejectsInjectedHeader checks that a tampered header fails the build
// rather than emitting injected source.
func TestParseRejectsInjectedHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkcs11t.h")
	body := "#define CKM_EVIL 1; var pwned = 1\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parse(path); err == nil {
		t.Fatal("parse accepted an injected macro value, want error")
	}
}

// TestParseAcceptsCleanHeader checks a well-formed header still parses.
func TestParseAcceptsCleanHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pkcs11t.h")
	body := strings.Join([]string{
		"#define CK_TRUE 1",
		"#define CKM_AES_CBC 0x00001082",
		"#define CKF_ARRAY_ATTRIBUTE 0x40000000",
		"#define CKR_OK 0x00000000",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	defs, err := parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(defs) != 4 {
		t.Fatalf("parsed %d defines, want 4", len(defs))
	}
	if defs[0].name != "CK_TRUE" || defs[0].value != "true" {
		t.Errorf("CK_TRUE = %q, want true", defs[0].value)
	}
}

// TestRenderErrorsOnlyCKR checks the error table includes only CKR_ names.
func TestRenderErrorsOnlyCKR(t *testing.T) {
	defs := []define{
		{name: "CKR_OK", value: "0x00000000"},
		{name: "CKM_AES_CBC", value: "0x00001082"},
		{name: "CKR_ARGUMENTS_BAD", value: "0x00000007"},
	}
	src, n, err := renderErrors("cryptoki", "pkcs11t.h", defs)
	if err != nil {
		t.Fatalf("renderErrors: %v", err)
	}
	if n != 2 {
		t.Errorf("renderErrors counted %d, want 2", n)
	}
	if strings.Contains(string(src), "CKM_AES_CBC") {
		t.Error("renderErrors emitted a non-CKR name")
	}
}
