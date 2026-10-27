<h1 align="center">
  @peculiar/x509
</h1>

<div align="center">

![NPM License](https://img.shields.io/npm/l/@peculiar/x509)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/PeculiarVentures/x509/publish.yml?branch=master&label=publish)
[![npm version](https://img.shields.io/npm/v/@peculiar/x509.svg)](https://www.npmjs.com/package/@peculiar/x509)
![Coveralls](https://img.shields.io/coverallsCoverage/github/PeculiarVentures/x509)
[![npm downloads](https://img.shields.io/npm/dm/@peculiar/x509.svg)](https://www.npmjs.com/package/@peculiar/x509)

</div>

- [About](#about)
- [Installation](#installation)
- [⚠️ Reflect Polyfill Required](#-reflect-polyfill-required)
- [Breaking Changes In v3](#breaking-changes-in-v3)
- [Documentation](#documentation)
- [Usage](#usage)
  - [Browser](#browser)
  - [Set a crypto provider](#set-a-crypto-provider)
- [Examples](#examples)
- [Contributing](#contributing)

## About

`@peculiar/x509` is a TypeScript/JavaScript library for X.509 certificates, certificate requests (PKCS#10), and certificate revocation lists (CRLs) in browsers and Node.js. It parses, creates, and verifies them with WebCrypto, builds certificate chains, and reads and writes PKCS#7 certificate lists. It is built on [`@peculiar/asn1-schema`](https://github.com/PeculiarVentures/asn1-schema).

## Installation

```bash
npm install @peculiar/x509 reflect-metadata
```

## ⚠️ Reflect Polyfill Required

**This library requires a Reflect API polyfill.** You must install one of the following and import it at the top of your entry point:

- [reflect-metadata](https://www.npmjs.com/package/reflect-metadata)
- [core-js](https://www.npmjs.com/package/core-js) (`core-js/full/reflect`)
- [@abraham/reflection](https://www.npmjs.com/package/@abraham/reflection)

**Example with reflect-metadata:**

```js
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
// ...
```

If you see the error **"tsyringe requires a reflect polyfill. Please add 'import "reflect-metadata"' to the top of your entry point."** — install one of the polyfills above and add the import before any `@peculiar/x509` imports.

## Breaking Changes In v3

v3 is ESM-only and requires Node.js `^20.19.0 || >=22.12.0` (was `>=20.0.0`). CommonJS code can still `require("@peculiar/x509")` on these versions; Node.js 20.0–20.18 and 22.0–22.11 can't. The public API is unchanged, and the Reflect polyfill is still required.

- **TypeScript compiling to CommonJS:** use `"module": "node20"` or `"nodenext"` (`node16` fails with TS1479). ESM and bundler setups need no changes.
- **Jest in CommonJS mode:** switch to ESM mode or Vitest, or configure an ESM-to-CommonJS transformer and make sure `transformIgnorePatterns` doesn't exclude `@peculiar/x509` and its ESM dependencies (`@peculiar/asn1-*`, `asn1js`, `@peculiar/utils`).
- **Deep imports** (`@peculiar/x509/build/x509.cjs.js`, `@peculiar/x509/build/x509.es.js`) are blocked by `exports`; import from `@peculiar/x509`.
- **No browser script bundle:** `build/x509.js` (the `x509` global for `<script>` tags) and the `unpkg`/`jsdelivr` fields are removed, so an unversioned `<script src="https://unpkg.com/@peculiar/x509">` stops working. Bundle the package or import it from esm.sh as a module (see [Browser](#browser)), or pin `@peculiar/x509@2` for the old script.
- **`@peculiar/asn1-schema` 3 is a peer dependency**, and the `@peculiar/asn1-*` packages move to 3 (which need `asn1js` 4). npm installs peers automatically; the app must end up with a single copy of each. ASN.1 objects built with asn1-schema 2 packages (for example a `Certificate` from `@peculiar/asn1-x509` 2) can't be passed to x509 3, so upgrade other libraries that use them at the same time.
- **`pvtsutils` is replaced by `@peculiar/utils` 4.** Hex input (serial numbers, key identifiers, `#` name values) is read as before. Byte input passed as a view (`Uint8Array`, `Buffer`) is now copied, so `rawData` no longer shares memory with it; Base64 text with line breaks, which v2 rejected as `raw` input, is decoded; and `SharedArrayBuffer` input is accepted.
- **Trailing data is rejected:** DER/BER input (certificates, CRLs, CSRs, public keys, extensions, PKCS#7 lists) that continues after the encoded structure throws `Unexpected data after the ASN.1 structure`. v2 ignored the extra bytes but kept them in `rawData` and thumbprints.
- **`@peculiar/webcrypto`** as the crypto provider: use 2.x, which shares asn1-schema 3 with x509. Next to asn1-schema 3, 1.x keeps two private asn1-schema 2 copies and its ECDSA signing fails with `Cannot get schema for 'EcDsaSignature' target`.

## Documentation

Documentation, the API reference, and runnable examples are at [peculiarventures.github.io/x509](https://peculiarventures.github.io/x509/).

## Usage

```js
import "reflect-metadata";
import * as x509 from "@peculiar/x509";

// Create a self-signed certificate with a WebCrypto key pair
const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const keys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
const cert = await x509.X509CertificateGenerator.createSelfSigned({
  name: "CN=Example",
  keys,
  signingAlgorithm: algorithm,
  extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
});
const pem = cert.toString("pem");

// Parse a certificate from PEM, Base64, hex, or DER and read it
const parsed = new x509.X509Certificate(pem);
console.log(parsed.subject); // CN=Example
console.log(await parsed.verify()); // true: self-signed and valid now
```

### Browser

Bundle `@peculiar/x509` with your app (Vite, webpack, esbuild, Rollup), or load the ESM build from a CDN that serves npm packages as browser modules, such as [esm.sh](https://esm.sh). Import the Reflect polyfill first:

```html
<script type="module">
  import "https://esm.sh/reflect-metadata";
  import * as x509 from "https://esm.sh/@peculiar/x509@3";

  const cert = new x509.X509Certificate(pem);
  console.log(cert.subject);
</script>
```

> WARN: Pin the version in the URL, and prefer bundling or hosting your own copy for production.

### Set a crypto provider

By default the library uses the platform's WebCrypto (`globalThis.crypto`), which browsers and Node.js provide. To use another WebCrypto implementation, for example [`@peculiar/webcrypto`](https://www.npmjs.com/package/@peculiar/webcrypto) 2.x for algorithms your platform lacks, set it as the provider:

```js
import * as x509 from "@peculiar/x509";
import { Crypto } from "@peculiar/webcrypto";

x509.cryptoProvider.set(new Crypto());
```

## Examples

Runnable examples are on the [website](https://peculiarventures.github.io/x509/docs/examples/):

- Certificates: [read a certificate](https://peculiarventures.github.io/x509/docs/examples/certificates/parse-certificate), [create a self-signed certificate](https://peculiarventures.github.io/x509/docs/examples/certificates/self-signed), [issue and verify a certificate](https://peculiarventures.github.io/x509/docs/examples/certificates/issue-certificate), [distinguished names](https://peculiarventures.github.io/x509/docs/examples/certificates/names)
- Certificate requests: [create a certificate request](https://peculiarventures.github.io/x509/docs/examples/requests/create-csr), [issue a certificate from a request](https://peculiarventures.github.io/x509/docs/examples/requests/sign-csr)
- Revocation: [create and check a CRL](https://peculiarventures.github.io/x509/docs/examples/revocation/crl)
- Chains and bundles: [build a certificate chain](https://peculiarventures.github.io/x509/docs/examples/chains/build-chain), [PKCS#7 files and PEM bundles](https://peculiarventures.github.io/x509/docs/examples/chains/pkcs7)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, commit conventions and the release flow.
