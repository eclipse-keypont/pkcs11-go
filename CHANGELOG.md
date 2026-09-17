<!--
SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
SPDX-License-Identifier: MIT
-->

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions here describe the Go API of the `cryptoki` and `p11` packages. They are
independent of the PKCS #11 specification revision the binding targets, which is
[OASIS PKCS #11 v3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html).

## [Unreleased]

## [1.1.1] - 2026-09-17

Security release: fixes six findings from the Synapse hunt of the `cryptoki`
package. None change the exported Go API; all are internal cgo memory-safety,
input-validation, and loader-hardening fixes.

### Security

- `GetAttributeValue` scrubbed each attribute's buffer using the length the
  token wrote back (`ulValueLen`) rather than the size that was allocated, so a
  token that reported a larger length left the tail of the buffer unscrubbed and
  could steer the `zfree`/`ck_memzero` span past the allocation (CWE-787). The
  allocation size is now recorded separately from the `CK_ATTRIBUTE` and used for
  both scrubbing and the copy back into Go.
- `outOp` — the two-pass length-query helper behind `Encrypt`, `Decrypt`,
  `Digest`, `Sign`, `GenerateRandom`, and friends — freed its scratch buffer
  using the mutable `*CK_ULONG` the callback fills in, and trusted that same
  length when copying the result into Go. A token that grew the length on the
  data pass could make `C.GoBytes` read past the allocation (CWE-787). The
  allocation capacity is now saved before the callback and used for cleanup, and
  the returned length is bounds-checked against it.
- `GetAttributeValue` passed nested array attributes (`CKA_WRAP_TEMPLATE`,
  `CKA_UNWRAP_TEMPLATE`, `CKA_DERIVE_TEMPLATE`, `CKA_ALLOWED_MECHANISMS`, or any
  type with `CKF_ARRAY_ATTRIBUTE` set) to the native call with their `pValue`
  left uninitialized, since the Go side never allocates for the nested template
  (CWE-824). Array attributes are now rejected up front with an error rather than
  handed to the token.
- `outOp` returned an empty result immediately when the sizing pass reported zero
  bytes, skipping the data pass entirely — so a zero-length `Encrypt`/`Sign`/
  `Digest` never ran the operation and never checked its return code (CWE-345).
  The data pass now always runs (allocating at least one byte to advertise a
  non-nil buffer), and its return status is checked before returning.
- The Windows module loader used `LOAD_WITH_ALTERED_SEARCH_PATH`, which lets a
  PKCS #11 module's DLL dependencies resolve from the application's working
  directory and other untrusted search locations (CWE-427). `LoadLibraryExA` now
  uses `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`, so
  dependencies resolve only from the module's own directory and the system
  directory. An empty module path is rejected up front.

### Fixed

- The integration test harness (`setupToken`) initialized the first free slot
  unconditionally, which would erase an already-initialized token if one was
  present (CWE-20). It now inspects each slot's token info and refuses to proceed
  unless it finds one not marked `CKF_TOKEN_INITIALIZED`.

## [1.1.0] - 2026-09-04

The final release of the 1.1.0 line. This section lists everything since 1.0.0,
including the changes first published in [1.1.0-rc1].

### Added

- `ULongSize`, `ULongToBytes`, and `BytesToULong` in `cryptoki` — the CK_ULONG
  codec, previously private as `ckULong`, is now exported in both directions.
  Cryptoki returns attribute values at the token's CK_ULONG width (8 bytes under
  LP64, 4 under Windows' LLP64), while a Go `uint` is 64 bits everywhere, so
  callers had to import `"C"` for `sizeof(CK_ULONG)` or guess. Consumers can now
  decode a CK_ULONG without cgo. `BytesToULong` zero-extends a value shorter than
  a CK_ULONG (SoftHSM returns a 4-byte `CKA_PARAMETER_SET`) and ignores anything
  past the first one, so a quirky token cannot make a caller read off the end.
  Refs [eclipse-keypont/crypto11#103](https://github.com/eclipse-keypont/crypto11/pull/103),
  where reinterpreting an attribute value as a `*uint` left garbage in the high
  half on Windows and broke `FindAllKeyPairs`.
- Native Go fuzz targets for the CK_ULONG codec (`ULongToBytes` / `BytesToULong`)
  and for `NewAttribute`'s `[]byte` and `string` encoding — the pure-Go paths
  that handle arbitrary token-supplied bytes rather than the cgo call boundary.
  Also satisfies OpenSSF Scorecard's Fuzzing check.
- `fuzz.yml` workflow running each target well past its seed corpus, triggered
  by pushing a `v*-rc*` tag or via `workflow_dispatch`.
- This changelog. GitHub Release notes are generated from commits and live only
  on the Releases page; the changelog ships inside the module and the signed
  source archive, where auditors and `go get` consumers can actually reach it.

### Changed

- The version is now derived from the git tags instead of being declared in the
  source. `cryptoki/version.go`, the `Release` variable it held, and the `release`
  build tag are all gone: `make release BUMP=major|minor|patch|rc|final` computes
  the next version from the newest `v*` tag, `make next` previews it, and
  `make version` reports `git describe`. A hand-maintained constant could drift
  from the tag it was supposed to name — `Release` had sat at 0.1.0 while the
  repository was tagged v1.1.0-rc1 — and there is no longer a constant to drift.
  `PRE=rc1` keeps a pre-release identifier on a major/minor/patch bump, and
  `VERSION=x.y.z` overrides the arithmetic.

### Fixed

- `make release` and `make version` could not run at all: `cryptoki/version.go`
  redeclared the `Version` type already defined in `cryptoki/types.go`, so the
  package failed to compile under `-tags release`. Neither target compiles Go
  code any more, and `make release` additionally refuses to tag unless this file
  carries a dated section for the computed version and the tag is unused.
- Makefile tool guards passed on a dead version-manager shim. `command -v` asks
  whether a name resolves, not whether it runs, and a goenv shim stays on PATH
  for every tool it has ever seen. The shared `require` macro now probes by
  running the tool and treats exit 127 as missing; applied to `golangci-lint`,
  `govulncheck`, `lint-fix` (previously unguarded), and `curl`.

### Documentation

- README records the project's place in [Eclipse Keypont](https://projects.eclipse.org/projects/technology.keypont),
  documents the changelog and the release procedure, and reworks the badge rows.

### Known limitations

- The Windows cgo build and the SoftHSM integration job are disabled in CI
  (`if: false` in `ci.yml`) pending fixes, so this release is verified by unit
  tests, lint, and the vulnerability and fuzz jobs only. Note that the CK_ULONG
  work above targets Windows' LLP64 width but is not currently exercised by a
  Windows CI run.

## [1.1.0-rc1] - 2026-08-03

Release candidate for [1.1.0]; see that section for the consolidated list.

## [1.0.0] - 2026-07-08

Initial release: a clean-room binding derived from the OASIS PKCS #11 v3.2
specification and its C headers, with no code copied from existing bindings.

### Added

- `cryptoki` — the low-level binding: module loading (Unix `dlopen`, Windows
  `LoadLibrary`), the full v2.x surface (slots, tokens, sessions, login, objects,
  attributes, find, digest, encrypt/decrypt, sign/verify, key generation,
  wrap/unwrap/derive, random), structured mechanism parameters (`NewGCMParams`,
  `NewOAEPParams`, `NewPSSParams`, `NewECDH1DeriveParams`), and the v3.2 entry
  points — ML-KEM encapsulate/decapsulate, stateless `VerifySignature`,
  authenticated wrap, and session validation flags — dispatched via the 3.2
  interface.
- `p11` — the high-level layer: `Module`, `Slot`, `Session`, `Object`, and typed
  `SecretKey` / `PublicKey` / `PrivateKey` / `KeyPair` values.
- `cmd/genconst` — clean-room generator producing `cryptoki/zconst.go` from the
  vendored OASIS headers, pinned at commit `858bfc8b`.
- Supply-chain pipeline: GPG/SSH-signed tags, a deterministic source archive with
  SHA-256 and a keyless cosign signature, SLSA3 provenance, and an end-to-end
  `slsa-verifier` job that fails the release rather than shipping broken
  provenance. Releases are gated on the lint and govulncheck workflows.
- CI: build and test, golangci-lint, CodeQL, govulncheck, dependency review,
  OpenSSF Scorecard, and gitleaks secret scanning, with all GitHub Actions
  pinned to commit SHAs.
- MIT `LICENSE` for the Go code, and `NOTICE.md` covering the OASIS copyright
  and IPR policy for the three headers vendored verbatim under
  `internal/headers/`.

[Unreleased]: https://github.com/eclipse-keypont/pkcs11-go/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/eclipse-keypont/pkcs11-go/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/eclipse-keypont/pkcs11-go/compare/v1.0.0...v1.1.0
[1.1.0-rc1]: https://github.com/eclipse-keypont/pkcs11-go/compare/v1.0.0...v1.1.0-rc1
[1.0.0]: https://github.com/eclipse-keypont/pkcs11-go/releases/tag/v1.0.0
