// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

package cryptoki

import "testing"

// TestMlockMunlockRoundTrip checks that a page-aligned buffer can be locked and
// unlocked. mlock requires page alignment, so the test allocates a page-sized
// slice; a failure is reported as a skip when the process lacks RLIMIT_MEMLOCK
// (common in unprivileged CI containers).
func TestMlockMunlockRoundTrip(t *testing.T) {
	buf := make([]byte, 4096)
	if err := Mlock(buf); err != nil {
		t.Skipf("mlock unavailable in this environment: %v", err)
	}
	if err := Munlock(buf); err != nil {
		t.Errorf("Munlock after Mlock = %v, want nil", err)
	}
}

// TestMlockEmptyIsNoop checks the empty-slice fast path.
func TestMlockEmptyIsNoop(t *testing.T) {
	if err := Mlock(nil); err != nil {
		t.Errorf("Mlock(nil) = %v, want nil", err)
	}
	if err := Munlock(nil); err != nil {
		t.Errorf("Munlock(nil) = %v, want nil", err)
	}
}
