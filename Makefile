# SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
# SPDX-License-Identifier: MIT
#
# Makefile for github.com/eclipse-keypont/pkcs11-go — PKCS #11 v3.2 binding.
#
# This is an independent, clean-room binding derived from the OASIS PKCS #11
# v3.2 specification and its C headers (inspired by miekg/pkcs11, no code copied).
#
# The three official OASIS PKCS #11 v3.2 headers are downloaded verbatim into
# internal/headers/ from the OASIS pkcs11 GitHub repository (commit
# 858bfc8b93ded02a40886e2321240b5978e1aa42). They must never be hand-edited.
# After any header refresh, re-run `make generate` to regenerate the constants.

OASIS_COMMIT := 858bfc8b93ded02a40886e2321240b5978e1aa42
OASIS        := https://raw.githubusercontent.com/oasis-tcs/pkcs11/$(OASIS_COMMIT)/published/3-02
HEADER_DIR   := internal/headers

.PHONY: all headers refresh-headers generate build test integration integration-v32 \
        clean-headers version release

all: headers generate build test

# ── Download official OASIS headers ──────────────────────────────────────────
headers: $(HEADER_DIR)/pkcs11t.h $(HEADER_DIR)/pkcs11f.h $(HEADER_DIR)/pkcs11.h

$(HEADER_DIR)/pkcs11t.h:
	curl -sSfL "$(OASIS)/pkcs11t.h" -o $@

$(HEADER_DIR)/pkcs11f.h:
	curl -sSfL "$(OASIS)/pkcs11f.h" -o $@

$(HEADER_DIR)/pkcs11.h:
	curl -sSfL "$(OASIS)/pkcs11.h" -o $@

# Force re-download even when files already exist, then record their digests.
refresh-headers:
	curl -sSfL "$(OASIS)/pkcs11t.h" -o $(HEADER_DIR)/pkcs11t.h
	curl -sSfL "$(OASIS)/pkcs11f.h" -o $(HEADER_DIR)/pkcs11f.h
	curl -sSfL "$(OASIS)/pkcs11.h"  -o $(HEADER_DIR)/pkcs11.h
	@cd $(HEADER_DIR) && sha256sum pkcs11f.h pkcs11.h pkcs11t.h
	@echo "Refreshed all three official OASIS v3.2 headers. Run 'make generate'."

# ── Code generation ──────────────────────────────────────────────────────────
# cryptoki/zconst.go is generated from internal/headers/pkcs11t.h by the
# //go:generate directive in cryptoki/doc.go (cmd/genconst). Must be re-run
# after `make headers` or `make refresh-headers`.
generate:
	go generate ./...

# ── Build ────────────────────────────────────────────────────────────────────
build:
	go build ./...

# ── Tests ────────────────────────────────────────────────────────────────────
test:
	go test ./...

# Integration tests use a single PKCS11_MODULE for both PKCS #11 v2.4 and v3.2.
#
# SoftHSMv3 (https://github.com/pqctoday/softhsmv3) is recommended because it
# implements v3.2 while remaining fully backward-compatible with v2.4.
# System-installed libsofthsm2.so also works; v3.2/PQC tests will self-skip.
#
# No external tools required — token initialisation is done entirely via the
# PKCS#11 API (C_InitToken / C_InitPIN).
#
# Build SoftHSMv3 from source:
#   git clone https://github.com/pqctoday/softhsmv3
#   cd softhsmv3
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build -j$(nproc)
#
# Run all integration tests (v2.4 compat + v3.2):
#   make integration PKCS11_MODULE=$PWD/softhsmv3/build/src/lib/libsofthsmv3.so
#
# Run only v3.2/PQC tests:
#   make integration-v32 PKCS11_MODULE=$PWD/softhsmv3/build/src/lib/libsofthsmv3.so

PKCS11_MODULE ?=
PKCS11_PIN    ?= 1234

integration:
	@if [ -z "$(PKCS11_MODULE)" ]; then \
	    echo ""; \
	    echo "Error: PKCS11_MODULE is not set."; \
	    echo ""; \
	    echo "Example:"; \
	    echo "  make integration PKCS11_MODULE=/path/to/libsofthsmv3.so"; \
	    echo ""; \
	    exit 1; \
	fi
	PKCS11_MODULE="$(PKCS11_MODULE)" PKCS11_PIN="$(PKCS11_PIN)" \
	    go test -v ./...

# Run only the v3.2 / PQC tests (faster when iterating on new algorithms):
# ML-KEM, ML-DSA, SLH-DSA, stateless verify, validation flags, key wrap.
V32_TESTS := TestIntegrationMLKEM|TestIntegrationMLDSA|TestIntegrationSLHDSA|TestIntegrationStatelessVerify|TestIntegrationGetSessionValidationFlags|TestIntegrationAESKeyWrap|TestIntegrationAuthenticatedWrap

integration-v32:
	@if [ -z "$(PKCS11_MODULE)" ]; then \
	    echo "Error: PKCS11_MODULE is not set."; \
	    exit 1; \
	fi
	PKCS11_MODULE="$(PKCS11_MODULE)" PKCS11_PIN="$(PKCS11_PIN)" \
	    go test -v -run '$(V32_TESTS)' ./...

# ── clean-headers ────────────────────────────────────────────────────────────
# Removes the downloaded OASIS headers (run `make headers` to restore them).
# Keeps platform.h and NOTICE.md, which are part of this repository.
clean-headers:
	rm -f $(HEADER_DIR)/pkcs11t.h $(HEADER_DIR)/pkcs11f.h $(HEADER_DIR)/pkcs11.h

# ── Release ───────────────────────────────────────────────────────────────────
# The version is the single source of truth in cryptoki/version.go (built with
# the `release` build tag). It is used to tag the git repository; no build
# artifacts are produced or uploaded.
#
#   * Bump Release in cryptoki/version.go
#   * Run: make release   (commits "Release $VERSION", tags v$VERSION, pushes)
#   * Or:  make version   (just print the current version)
#
# All release logic lives inside these recipes so that ordinary targets never
# compile or run the version probe. The probe is a throwaway main package that
# prints cryptoki.Release; it is written, run, and removed within one shell.
define VERSION_PROBE
//go:build ignore

package main

import (
	"fmt"

	"github.com/eclipse-keypont/pkcs11-go/cryptoki"
)

func main() { fmt.Println(cryptoki.Release.String()) }
endef
export VERSION_PROBE

version:
	@printf '%s\n' "$$VERSION_PROBE" > version_release.go
	@go run -tags release version_release.go; rm -f version_release.go

release:
	@printf '%s\n' "$$VERSION_PROBE" > version_release.go
	@v=$$(go run -tags release version_release.go); rm -f version_release.go; \
	echo "Committing release $$v"; \
	git commit -am "Release $$v"; \
	git tag "v$$v"; \
	echo "Pushing release $$v"; \
	git push --tags; \
	git push; \
	echo "Released $$v"
