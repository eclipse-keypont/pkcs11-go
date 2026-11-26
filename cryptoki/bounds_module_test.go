// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import (
	"path/filepath"
	"testing"
)

// TestModuleReportedCountsAreBounded checks that a count or a length the module
// reports is checked against the buffer it was given, or against the size
// limit, before the binding indexes or allocates with it. The mock reports
// more than it was given everywhere; each call must fail with an error rather
// than panic.
func TestModuleReportedCountsAreBounded(t *testing.T) {
	ctx, err := New(compileTestModule(t, filepath.Join("testdata", "countmock", "mock.c")))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ctx.Destroy()

	if got, err := ctx.GetSlotList(false); err == nil {
		t.Errorf("GetSlotList = %v, want an error for a count larger than the list", got)
	}
	if got, err := ctx.GetMechanismList(0); err == nil {
		t.Errorf("GetMechanismList = %v, want an error for a count larger than the list", got)
	}
	if got, err := ctx.FindObjects(1, 4); err == nil {
		t.Errorf("FindObjects = %v, want an error for a count larger than the buffer", got)
	}
	if got, err := ctx.GetAttributeValue(1, 1, []*Attribute{NewAttribute(CKA_VALUE, nil)}); err == nil {
		t.Errorf("GetAttributeValue = %v, want an error for a length over the limit", got)
	}
}
