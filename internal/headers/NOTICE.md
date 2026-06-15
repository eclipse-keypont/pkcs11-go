# Vendored OASIS PKCS #11 headers

This directory vendors three header files **verbatim** from the OASIS PKCS #11
Technical Committee:

| File         | Origin                                              |
|--------------|-----------------------------------------------------|
| `pkcs11.h`   | OASIS PKCS #11 v3.2 — general include header         |
| `pkcs11t.h`  | OASIS PKCS #11 v3.2 — type and constant definitions  |
| `pkcs11f.h`  | OASIS PKCS #11 v3.2 — function list / X-macro list   |

Upstream source: <https://github.com/oasis-tcs/pkcs11>
Specification:   <https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html>

`platform.h` in this directory is **not** an OASIS file. It is original work
(Copyright © 2026 The Eclipse Foundation and pkcs11-go Authors, MIT) that supplies the five
platform-configuration macros the OASIS headers require callers to define, per
the documentation block at the top of `pkcs11.h`.

## License of the OASIS headers

Each OASIS header carries this notice, which is retained unmodified:

> Copyright (c) OASIS Open 2016, 2019, 2024. All Rights Reserved.
> Distributed under the terms of the OASIS IPR Policy,
> [http://www.oasis-open.org/policies-guidelines/ipr], AS-IS, WITHOUT ANY
> IMPLIED OR EXPRESS WARRANTY; there is no warranty of MERCHANTABILITY, FITNESS
> FOR A PARTICULAR PURPOSE or NONINFRINGEMENT of the rights of others.

The OASIS IPR Policy permits reproduction and distribution of these published
header files. Their OASIS copyright **must remain intact** — do not edit these
three `.h` files. If they need updating, replace them with fresh upstream copies
(`make refresh-headers`) and re-run `make generate`.

The MIT license that covers the rest of this repository applies to the original
Go code and `platform.h`, **not** to the OASIS-copyrighted headers, which remain
under the OASIS notice above.

## Integrity

Recorded SHA-256 digests of the vendored upstream headers:

```
3a205ff9a12247108193d124571fac88e38b59f1273e462baa1b5e00cd182fa0  pkcs11f.h
bbc8a26569ce56e0dea540f03dffd56be305175e8e61cad2b8fffd7c65dbf6d8  pkcs11.h
95738fdcd9b5c9c73f55f9132aefa87354556cec1c46f681b8a2000b8b5dbccb  pkcs11t.h
```
