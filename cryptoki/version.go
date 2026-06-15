// SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
// SPDX-License-Identifier: MIT

//go:build release

package cryptoki

import "fmt"

// Release is the current version of this binding. It is read by
// Makefile.release (built with -tags release) to derive the git tag.
var Release = Version{Major: 0, Minor: 1, Patch: 0}

// Version is a semantic version triple for this library.
type Version struct {
	Major, Minor, Patch int
}

// String renders the version as "major.minor.patch".
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}
