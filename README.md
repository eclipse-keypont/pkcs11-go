# pkcs11-go

[![Build](https://github.com/eclipse-keypont/pkcs11-go/actions/workflows/ci.yml/badge.svg)](https://github.com/eclipse-keypont/pkcs11-go/actions/workflows/ci.yml)
[![Lint](https://github.com/eclipse-keypont/pkcs11-go/actions/workflows/lint.yml/badge.svg)](https://github.com/eclipse-keypont/pkcs11-go/actions/workflows/lint.yml)
[![Secret Scan](https://github.com/eclipse-keypont/pkcs11-go/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/eclipse-keypont/pkcs11-go/actions/workflows/secret-scan.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/eclipse-keypont/pkcs11-go/badge)](https://scorecard.dev/viewer/?uri=github.com/eclipse-keypont/pkcs11-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/eclipse-keypont/pkcs11-go)](https://goreportcard.com/report/github.com/eclipse-keypont/pkcs11-go)
[![GitHub release](https://img.shields.io/github/v/release/eclipse-keypont/pkcs11-go)](https://github.com/eclipse-keypont/pkcs11-go/releases/latest)

A Go binding for the [OASIS PKCS #11 (Cryptoki) v3.2][spec] cryptographic token
interface, including post-quantum (ML-KEM / ML-DSA) and other v3.2 additions.

```
import "github.com/eclipse-keypont/pkcs11-go/cryptoki"
```

## Quick start

The `p11` package provides an ergonomic, object-oriented API over the raw
`cryptoki` binding.

```go
import (
    "github.com/eclipse-keypont/pkcs11-go/cryptoki"
    "github.com/eclipse-keypont/pkcs11-go/p11"
)

// Open the module and initialize.
mod, err := p11.OpenModule("/path/to/libsofthsmv3.so")
if err != nil {
    log.Fatal(err)
}
defer mod.Close()

// Find a token by label (all slots including empty ones).
all, _ := mod.AllSlots()
var slot p11.Slot
for _, s := range all {
    if ti, err := s.TokenInfo(); err == nil && ti.Label == "mytoken" {
        slot = s
        break
    }
}

// Open a read-write session and log in.
sess, err := slot.OpenWriteSession()
if err != nil {
    log.Fatal(err)
}
defer sess.Close()
if err := sess.Login([]byte("1234")); err != nil {
    log.Fatal(err)
}
defer sess.Logout()

// Generate an AES-256 key.
key, err := sess.GenerateKey(
    cryptoki.NewMechanism(cryptoki.CKM_AES_KEY_GEN, nil),
    []*cryptoki.Attribute{
        cryptoki.NewAttribute(cryptoki.CKA_TOKEN, true),
        cryptoki.NewAttribute(cryptoki.CKA_LABEL, "my-aes-key"),
        cryptoki.NewAttribute(cryptoki.CKA_VALUE_LEN, 32),
        cryptoki.NewAttribute(cryptoki.CKA_ENCRYPT, true),
        cryptoki.NewAttribute(cryptoki.CKA_DECRYPT, true),
    },
)
if err != nil {
    log.Fatal(err)
}

// Encrypt and decrypt with AES-CBC-PAD.
iv, _ := sess.GenerateRandom(16)
mech := cryptoki.NewMechanism(cryptoki.CKM_AES_CBC_PAD, iv)
ct, err := key.Encrypt(mech, []byte("hello, token"))
if err != nil {
    log.Fatal(err)
}
pt, err := key.Decrypt(mech, ct)
fmt.Println(string(pt)) // hello, token

// Find a key created in a previous session.
found, err := sess.FindSecretKey("my-aes-key")
if err != nil {
    log.Fatal(err)
}
label, _ := found.Object().Label()
fmt.Println(label) // my-aes-key

// Generate an RSA key pair and sign.
kp, err := sess.GenerateKeyPair(
    cryptoki.NewMechanism(cryptoki.CKM_RSA_PKCS_KEY_PAIR_GEN, nil),
    []*cryptoki.Attribute{
        cryptoki.NewAttribute(cryptoki.CKA_TOKEN, false),
        cryptoki.NewAttribute(cryptoki.CKA_MODULUS_BITS, 2048),
        cryptoki.NewAttribute(cryptoki.CKA_PUBLIC_EXPONENT, []byte{0x01, 0x00, 0x01}),
        cryptoki.NewAttribute(cryptoki.CKA_VERIFY, true),
    },
    []*cryptoki.Attribute{
        cryptoki.NewAttribute(cryptoki.CKA_TOKEN, false),
        cryptoki.NewAttribute(cryptoki.CKA_SIGN, true),
    },
)
if err != nil {
    log.Fatal(err)
}
sigMech := cryptoki.NewMechanism(cryptoki.CKM_SHA256_RSA_PKCS, nil)
sig, err := kp.Private.Sign(sigMech, []byte("message"))
if err != nil {
    log.Fatal(err)
}
if err := kp.Public.Verify(sigMech, []byte("message"), sig); err != nil {
    log.Fatal(err)
}

// Copy an existing object with a new label.
copy, err := found.Object().Copy([]*cryptoki.Attribute{
    cryptoki.NewAttribute(cryptoki.CKA_LABEL, "my-aes-key-backup"),
})
if err != nil {
    log.Fatal(err)
}
defer copy.Destroy()

// ML-KEM (FIPS 203) encapsulation / decapsulation (v3.2 module required).
if mod.SupportsV32() {
    mlkemKP, _ := sess.GenerateKeyPair(
        cryptoki.NewMechanism(cryptoki.CKM_ML_KEM_KEY_PAIR_GEN, nil),
        []*cryptoki.Attribute{
            cryptoki.NewAttribute(cryptoki.CKA_TOKEN, false),
            cryptoki.NewAttribute(cryptoki.CKA_PARAMETER_SET, uint(cryptoki.CKP_ML_KEM_768)),
            cryptoki.NewAttribute(cryptoki.CKA_ENCAPSULATE, true),
        },
        []*cryptoki.Attribute{
            cryptoki.NewAttribute(cryptoki.CKA_TOKEN, false),
            cryptoki.NewAttribute(cryptoki.CKA_DECAPSULATE, true),
        },
    )
    sharedKeyTemplate := []*cryptoki.Attribute{
        cryptoki.NewAttribute(cryptoki.CKA_CLASS, uint(cryptoki.CKO_SECRET_KEY)),
        cryptoki.NewAttribute(cryptoki.CKA_KEY_TYPE, uint(cryptoki.CKK_AES)),
        cryptoki.NewAttribute(cryptoki.CKA_VALUE_LEN, 32),
        cryptoki.NewAttribute(cryptoki.CKA_TOKEN, false),
        cryptoki.NewAttribute(cryptoki.CKA_ENCRYPT, true),
        cryptoki.NewAttribute(cryptoki.CKA_DECRYPT, true),
    }
    ciphertext, encKey, _ := mlkemKP.Public.Encapsulate(
        cryptoki.NewMechanism(cryptoki.CKM_ML_KEM, nil), sharedKeyTemplate)
    decKey, _ := mlkemKP.Private.Decapsulate(
        cryptoki.NewMechanism(cryptoki.CKM_ML_KEM, nil), ciphertext, sharedKeyTemplate)
    _ = encKey
    _ = decKey // encKey and decKey hold the same shared secret
}
```

The `cryptoki` package gives direct access to every PKCS #11 entry point for
callers that need finer control (streaming multi-part operations, attribute
queries, slot event polling, operation-state save/restore, etc.).

## Background & OASIS C header provenance

`github.com/eclipse-keypont/pkcs11-go` is a **clean-room implementation** of OASIS PKCS#11 in Golang. Every constant, type, and
function signature is derived directly from the OASIS PKCS #11 v3.2 specification
and its official C headers (`pkcs11.h`, `pkcs11t.h`, `pkcs11f.h`). The constant
set is regenerated from those headers by our own generator (`cmd/genconst`).

The three C headers vendored under [`internal/headers/`](./internal/headers/) are
taken **verbatim** from the official OASIS PKCS #11 Technical Committee repository:

| File        | Role                                                     |
|-------------|----------------------------------------------------------|
| `pkcs11.h`  | Top-level include                                        |
| `pkcs11t.h` | All types, structures, and constants                     |
| `pkcs11f.h` | Function-list X-macros (one entry per Cryptoki function) |

**Exact source:**

```
Repository : https://github.com/oasis-tcs/pkcs11
Commit     : 858bfc8b93ded02a40886e2321240b5978e1aa42
Path       : published/3-02/
Spec       : PKCS #11 Cryptoki v3.2
             https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
```

**SHA-256 integrity digests:**

```
3a205ff9a12247108193d124571fac88e38b59f1273e462baa1b5e00cd182fa0  pkcs11f.h
bbc8a26569ce56e0dea540f03dffd56be305175e8e61cad2b8fffd7c65dbf6d8  pkcs11.h
95738fdcd9b5c9c73f55f9132aefa87354556cec1c46f681b8a2000b8b5dbccb  pkcs11t.h
```

These files are **never hand-edited**. To verify integrity or re-fetch from the
pinned commit:

```bash
make refresh-headers   # re-downloads from the exact commit above and prints sha256sums
```

The full OASIS copyright notice and IPR policy statement for these headers is in
[`internal/headers/NOTICE.md`](./internal/headers/NOTICE.md).

## State of the Art: Other Go PKCS #11 Projects

This section compares `github.com/eclipse-keypont/pkcs11-go` to other projects.

### `github.com/miekg/pkcs11`

> This is a SOTA as of June 2026. Project `miekg/pkcs11` might add new features in the future, including support for PKCS#11 v3.2. We did [miekg/pkcs11/pull/191](https://github.com/miekg/pkcs11/pull/191) for this prior to choose to create a new clean-room implementation with `eclipse-keypont/pkcs11-go`.

[`miekg/pkcs11`][miekg] is a widely used Go PKCS #11 binding and covers
the v2.x API well. `github.com/eclipse-keypont/pkcs11-go` is an independent
project with different goals than `miekg/pkcs11`:

- **PKCS #11 v3.2** — full support for post-quantum algorithms (ML-KEM, ML-DSA,
  SLH-DSA), stateless verify, authenticated wrap, and KEM encapsulation /
  decapsulation; `miekg/pkcs11` targets older PKCS11 v2.x
- **Security hardening** — PINs and sensitive buffers are passed as `[]byte` and
  scrubbed (zeroed) before being freed; attribute value buffers holding key
  material are zeroised on release
- **Layered API** — `cryptoki` for direct, low-level control; `p11` for an
  ergonomic object-oriented interface on top
- **Clean-room constants** — generated directly from the vendored OASIS headers
  at a pinned commit, not transcribed by hand

No code is shared between the two projects. The only common ground is the shape
of the underlying C API, which is fixed by the OASIS standard.

[spec]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html
[miekg]: https://github.com/miekg/pkcs11

## License

- The Go code and `internal/headers/platform.h` are MIT licensed —
  Copyright © 2026 The Eclipse Foundation. See [LICENSE](./LICENSE).
- The three vendored OASIS headers under [`internal/headers/`](./internal/headers/)
  remain under their own OASIS copyright and the OASIS IPR Policy; they are
  redistributed verbatim. See [internal/headers/NOTICE.md](./internal/headers/NOTICE.md).

## Layout

```
pkcs11-go/
├── cryptoki/            # low-level cgo binding (Ctx, types, errors, params)
│   ├── doc.go           #   package doc + //go:generate directive
│   ├── zconst.go        #   generated constants (DO NOT EDIT)
│   └── version.go       #   release version (build tag: release)
├── p11/                 # high-level, object-oriented helpers (built on cryptoki)
├── cmd/genconst/        # clean-room header→constants generator
├── internal/headers/    # vendored OASIS v3.2 headers + platform.h shim + NOTICE
└── Makefile             # headers / generate / build / test / integration / release
```

## Building from the headers

The OASIS headers are vendored at the pinned commit above. To regenerate the
Go constants after a header refresh:

```bash
make refresh-headers   # re-fetch from the pinned commit, print sha256sums
make generate          # regenerate cryptoki/zconst.go from pkcs11t.h
make build test        # compile and run unit tests
```

## Linting

CI runs [golangci-lint][golangci] (v2) via `.golangci.yml`. Run the same checks
locally before pushing:

```bash
# One-time install of the v2 binary (matches CI's `version: latest`):
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
# Ensure $(go env GOPATH)/bin is on your PATH, then:

make lint       # report issues (same as the CI Lint workflow)
make lint-fix   # auto-fix the mechanically-fixable findings
```

Linting compiles cgo, so a C toolchain (`gcc`/`clang`) is required; no HSM is
needed.

[golangci]: https://golangci-lint.run

## Testing against a real token

Unit tests need no HSM. Integration tests load a PKCS #11 module via
`PKCS11_MODULE`. [SoftHSMv3][softhsm] is recommended for full v3.2 / PQC
coverage; `libsofthsm2.so` also works and the v3.2-only tests self-skip.

```bash
make integration PKCS11_MODULE=/path/to/libsofthsmv3.so
```

[softhsm]: https://github.com/pqctoday-org/pqctoday-hsm

## Status

Implemented and tested against SoftHSMv3 (PKCS #11 v3.2):

- **`cryptoki`** — the low-level binding: module loading (Unix `dlopen` / Windows
  `LoadLibrary`), the full v2.x surface (slots, tokens, sessions, login, objects,
  attributes, find, digest, encrypt/decrypt, sign/verify, key generation,
  wrap/unwrap/derive, random), structured mechanism parameters
  (`NewGCMParams`/`NewOAEPParams`/`NewPSSParams`/`NewECDH1DeriveParams`), and the
  v3.2 entry points (ML-KEM encapsulate/decapsulate, stateless `VerifySignature`,
  authenticated wrap, session validation flags) dispatched via the 3.2 interface.
- **`p11`** — the high-level layer: `Module`, `Slot`, `Session`, `Object`, and
  typed `SecretKey` / `PublicKey` / `PrivateKey` / `KeyPair` values.

Coverage: ML-KEM, ML-DSA, SLH-DSA, AES-GCM/CBC, RSA-OAEP/PKCS, ECDH1, AES key
wrap, and authenticated wrap all round-trip in the integration suite.
