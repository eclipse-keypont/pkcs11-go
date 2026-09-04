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
CHANGELOG    := CHANGELOG.md

.PHONY: all headers refresh-headers generate build vet test integration integration-v32 \
        lint lint-fix govulncheck clean-headers version next release

all: headers generate build test

# ── Tool preconditions ───────────────────────────────────────────────────────
# $(call require,<binary>,<how to install it>) — fail early with an install hint.
#
# Probes by running the tool, not `command -v`: a goenv shim stays on PATH even
# when the tool is not installed for the active Go version, so `command -v` says
# yes and the build dies later. Exit 127 (missing binary or dead shim) is the
# only status treated as missing; tools without --version exit 1 or 2 and pass.
#
# A hint must not contain a comma — make would read it as another $(call) argument.
define require
@$(1) --version >/dev/null 2>&1; \
if [ $$? -eq 127 ]; then \
    echo "$(1) not found. Install it with:"; \
    echo "  $(2)"; \
    exit 1; \
fi
endef

# ── Download official OASIS headers ──────────────────────────────────────────
headers: $(HEADER_DIR)/pkcs11t.h $(HEADER_DIR)/pkcs11f.h $(HEADER_DIR)/pkcs11.h

$(HEADER_DIR)/pkcs11t.h:
	$(call require,curl,sudo apt-get install curl)
	curl -sSfL "$(OASIS)/pkcs11t.h" -o $@

$(HEADER_DIR)/pkcs11f.h:
	$(call require,curl,sudo apt-get install curl)
	curl -sSfL "$(OASIS)/pkcs11f.h" -o $@

$(HEADER_DIR)/pkcs11.h:
	$(call require,curl,sudo apt-get install curl)
	curl -sSfL "$(OASIS)/pkcs11.h" -o $@

# Force re-download even when files already exist, then record their digests.
refresh-headers:
	$(call require,curl,sudo apt-get install curl)
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

# ── Vet ──────────────────────────────────────────────────────────────────────
vet:
	go vet ./...

# ── Lint ─────────────────────────────────────────────────────────────────────
# Runs golangci-lint (v2) against .golangci.yml — the same checks as the CI
# Lint workflow, so you can catch issues before pushing. cgo needs a C toolchain
# (gcc/clang); SoftHSM is NOT required for linting.
#
# Install the linter (v2, matching CI's `version: latest`):
#   go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
# Ensure $(go env GOPATH)/bin is on your PATH, then `golangci-lint version`.
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_INSTALL_HINT := go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

lint:
	$(call require,$(GOLANGCI_LINT),$(GOLANGCI_LINT_INSTALL_HINT))
	$(GOLANGCI_LINT) run ./...

# Auto-fix the mechanically-fixable findings (formatting, some conversions):
lint-fix:
	$(call require,$(GOLANGCI_LINT),$(GOLANGCI_LINT_INSTALL_HINT))
	$(GOLANGCI_LINT) run --fix ./...

# ── Vulnerability scan ───────────────────────────────────────────────────────
# Runs govulncheck (reachability-aware, cross-checked against the Go vuln DB) —
# the same check as the CI govulncheck workflow (.github/workflows/govulncheck.yml).
#
# Install govulncheck:
#   go install golang.org/x/vuln/cmd/govulncheck@latest
GOVULNCHECK ?= govulncheck

govulncheck:
	$(call require,$(GOVULNCHECK),go install golang.org/x/vuln/cmd/govulncheck@latest)
	$(GOVULNCHECK) -show verbose ./...

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
# Keeps platform.h, which is part of this repository.
clean-headers:
	rm -f $(HEADER_DIR)/pkcs11t.h $(HEADER_DIR)/pkcs11f.h $(HEADER_DIR)/pkcs11.h

# ── Release ───────────────────────────────────────────────────────────────────
# Git tags are the single source of truth for the version: nothing in the Go
# code carries one. `make release` derives the next version from the most recent
# v* tag and the bump you ask for; no build artifacts are produced or uploaded.
#
#   * make version           print what git says HEAD is (git describe)
#   * make next BUMP=minor   print the version that BUMP would cut
#   * Rename CHANGELOG.md's "## [Unreleased]" to "## [$VERSION] - <date>"
#   * make release BUMP=minor  (commits "Release $VERSION", tags, pushes)
#
# BUMP, applied to the newest v* tag (say v1.1.0-rc1 or v1.1.0):
#
#   major  1.1.0-rc1 -> 2.0.0     minor  1.1.0-rc1 -> 1.2.0
#   patch  1.1.0-rc1 -> 1.1.1     rc     1.1.0-rc1 -> 1.1.0-rc2
#   final  1.1.0-rc1 -> 1.1.0
#
# major/minor/patch drop any pre-release identifier, so they always move to a
# final version; add PRE to keep one (BUMP=minor PRE=rc1 -> 1.2.0-rc1), which is
# how the first candidate of a new line is cut. rc increments the trailing digits
# of the current identifier and so requires the newest tag to have one; final
# strips it. VERSION=x.y.z overrides the whole computation — the escape hatch for
# the first tag in a repository or a version this arithmetic will not produce.
#
# The changelog step is enforced, not documented: `make release` refuses to tag
# unless CHANGELOG.md carries a dated section for the computed version. It is
# easy to forget, and a tag cannot be taken back. Cutting a tag that already
# exists is refused for the same reason.
#
# The tag is created with `git tag -s` (GPG/SSH-signed, per your git signing
# config) so consumers can `git verify-tag v$VERSION`. Pushing the tag triggers
# .github/workflows/release.yml, which builds a signed source archive with SLSA3
# provenance. `go get` consumers still rely on go.sum + sum.golang.org.
#
# NEXT_VERSION prints the version BUMP/VERSION select, and is the one place that
# arithmetic lives; both `next` and `release` read it. It needs the tags to be
# present locally — a shallow or tagless clone (CI's default checkout) can only
# use VERSION.
define NEXT_VERSION
set -eu
if [ -n "$${VERSION:-}" ]; then printf '%s\n' "$$VERSION"; exit 0; fi
case "$${BUMP:-}" in
    major|minor|patch|rc|final) ;;
    "") echo "BUMP is not set. Use one of:" >&2
        echo "  make release BUMP=major|minor|patch|rc|final [PRE=rc1]" >&2
        echo "  make release VERSION=1.2.0" >&2
        exit 1 ;;
    *)  echo "BUMP=$$BUMP is not one of major, minor, patch, rc, final." >&2
        exit 1 ;;
esac
last=$$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)
if [ -z "$$last" ]; then
    echo "No v* tag found: nothing to bump from." >&2
    echo "  Fetch the tags (git fetch --tags), or cut the first release with" >&2
    echo "  make release VERSION=1.0.0" >&2
    exit 1
fi
base=$${last#v}
pre=""
case $$base in
    *-*) pre=$${base#*-}; base=$${base%%-*} ;;
esac
major=$${base%%.*}
rest=$${base#*.}
minor=$${rest%%.*}
patch=$${rest#*.}
case "$$BUMP" in
    major)  major=$$((major + 1)); minor=0; patch=0; pre=$${PRE:-} ;;
    minor)  minor=$$((minor + 1)); patch=0; pre=$${PRE:-} ;;
    patch)  patch=$$((patch + 1)); pre=$${PRE:-} ;;
    final)
        if [ -z "$$pre" ]; then
            echo "BUMP=final needs $$last to be a pre-release; it is already final." >&2
            exit 1
        fi
        pre="" ;;
    rc)
        if [ -z "$$pre" ]; then
            echo "BUMP=rc needs $$last to carry a pre-release identifier." >&2
            echo "  For the first candidate of a new version, name the bump it" >&2
            echo "  belongs to: make release BUMP=minor PRE=rc1" >&2
            exit 1
        fi
        stem=$$(printf '%s' "$$pre" | sed 's/[0-9]*$$//')
        num=$$(printf '%s' "$$pre" | sed 's/^.*[^0-9]//')
        pre="$$stem$$((num + 1))" ;;
esac
v="$$major.$$minor.$$patch"
if [ -n "$$pre" ]; then v="$$v-$$pre"; fi
printf '%s\n' "$$v"
endef
export NEXT_VERSION

# What git says HEAD is: the newest tag, commits since it, the abbreviated SHA,
# and -dirty when the tree has uncommitted changes.
version:
	@git describe --tags --always --dirty 2>/dev/null \
	    || { echo "not a git repository (or no commits yet)" >&2; exit 1; }

next:
	@sh -c "$$NEXT_VERSION"

release:
	@v=$$(sh -c "$$NEXT_VERSION"); \
	if git rev-parse -q --verify "refs/tags/v$$v" >/dev/null; then \
	    echo "Tag v$$v already exists."; \
	    exit 1; \
	fi; \
	if ! grep -q "^## \[$$v\] - " $(CHANGELOG); then \
	    echo "$(CHANGELOG) has no released section for $$v."; \
	    echo "  Rename '## [Unreleased]' to '## [$$v] - $$(date +%Y-%m-%d)',"; \
	    echo "  then update the link definitions at the foot of the file."; \
	    exit 1; \
	fi; \
	echo "Committing release $$v"; \
	git commit -am "Release $$v"; \
	git tag -s "v$$v" -m "Release v$$v"; \
	echo "Pushing release $$v"; \
	git push --tags; \
	git push; \
	echo "Released $$v"
