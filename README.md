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
- [⚠️ Reflect Polyfill Required](#-reflect-polyfill-required)
- [Installation](#installation)
- [Breaking Changes In v3](#breaking-changes-in-v3)
- [Documentation](#documentation)
- [Usage](#usage)
  - [Browser](#browser)
  - [Set crypto provider for Node.js](#set-crypto-provider-for-nodejs)
  - [Create a self-signed certificate](#create-a-self-signed-certificate)
  - [Parse a X509 certificate](#parse-a-x509-certificate)
  - [Create a PKCS#10 certificate request](#create-a-pkcs10-certificate-request)
  - [Decoded X509 certificate](#decoded-x509-certificate)
  - [Verify a certificate](#verify-a-certificate)
  - [Build a certificate chain](#build-a-certificate-chain)
  - [Export a list of X509 certificates to PKCS#7 format](#export-a-list-of-x509-certificates-to-pkcs7-format)

## About

`@peculiar/x509` is an easy to use TypeScript/Javascript library based on `@peculiar/asn1-schema` that makes generating X.509 Certificates and Certificate Requests as well as validating certificate chains easy.

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

## Installation

```
npm install @peculiar/x509
```

## Breaking Changes In v3

v3 is ESM-only and requires Node.js `^20.19.0 || >=22.12.0` (was `>=20.0.0`). CommonJS code can still `require("@peculiar/x509")` on these versions; Node.js 20.0–20.18 and 22.0–22.11 can't. The public API is unchanged, and the Reflect polyfill is still required.

- **TypeScript compiling to CommonJS:** use `"module": "node20"` or `"nodenext"` (`node16` fails with TS1479). ESM and bundler setups need no changes.
- **Jest in CommonJS mode:** switch to ESM mode or Vitest, or configure an ESM-to-CommonJS transformer and make sure `transformIgnorePatterns` doesn't exclude `@peculiar/x509` and its ESM dependencies (`@peculiar/asn1-*`, `asn1js`, `@peculiar/utils`).
- **Deep imports** (`@peculiar/x509/build/x509.cjs.js`, `@peculiar/x509/build/x509.es.js`) are blocked by `exports`; import from `@peculiar/x509`.
- **No browser script bundle:** `build/x509.js` (the `x509` global for `<script>` tags) and the `unpkg`/`jsdelivr` fields are removed, so an unversioned `<script src="https://unpkg.com/@peculiar/x509">` stops working. Bundle the package or import it from esm.sh as a module (see [Browser](#browser)), or pin `@peculiar/x509@2` for the old script.
- **`@peculiar/asn1-schema` 3 is a peer dependency**, and the `@peculiar/asn1-*` packages move to 3 (which need `asn1js` 4). npm installs peers automatically; the app must end up with a single copy of each. ASN.1 objects built with asn1-schema 2 packages (for example a `Certificate` from `@peculiar/asn1-x509` 2) can't be passed to x509 3, so upgrade other libraries that use them at the same time.
- **`@peculiar/webcrypto`** as the crypto provider: use 2.x, which shares asn1-schema 3 with x509. Next to asn1-schema 3, 1.x keeps two private asn1-schema 2 copies and its ECDSA signing fails with `Cannot get schema for 'EcDsaSignature' target`.

## Documentation

[https://peculiarventures.github.io/x509/](https://peculiarventures.github.io/x509/)

## Usage

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

A simple web application examples

- [Generate X509 certificate](https://codesandbox.io/s/generate-cert-fjwfh)
- [Generate PKCS#10 certificate request](https://codesandbox.io/s/generate-csr-0qhed)

### Set crypto provider for Node.js

In some cases you may want to use a different cryptographic implementation, for example when you want to work with an object that supports a cryptographic algorithm not supported by the platform you are on.

In these cases you can set a custom provider, these providers need to be compatible with the WebCrypto API, for example on NodeJS you can use `@peculiar/webcrypto` to allow `@peculiar/x509` to work the same as it does in browser!

```js
import * as x509 from "@peculiar/x509";
import { Crypto } from "@peculiar/webcrypto";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);
```

### Create a self-signed certificate

```js
const alg = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2048,
};
const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
const cert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: "01",
  name: "CN=Test",
  notBefore: new Date("2020/01/01"),
  notAfter: new Date("2020/01/02"),
  signingAlgorithm: alg,
  keys,
  extensions: [
    new x509.BasicConstraintsExtension(true, 2, true),
    new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
  ],
});

console.log(cert.toString("pem")); // Certificate in PEM format
```

### Parse a x509 certificate

```js
const base64 = "MIIDljCCAn6gAwIBAgIOSETcxtRwD...S+kAFXIwugUGYEnTWp0m5bAn5NlD314IEOg4mnS8Q==";

const cert = new x509.X509Certificate(base64);
console.log(cert.subject); // CN=Test, O=PeculiarVentures LLC
```

### Create a PKCS#10 certificate request

```js
const alg = {
  name: "ECDSA",
  namedCurve: "P-384",
  hash: "SHA-384",
};
const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
const csr = await x509.Pkcs10CertificateRequestGenerator.create({
  name: "CN=Test",
  keys,
  signingAlgorithm: alg,
  extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment)],
  attributes: [new x509.ChallengePasswordAttribute("password")],
});

console.log(csr.toString("base64")); // Certificate request in Base64 format
```

### Decoded X509 certificate

```js
X509Certificate {
  rawData: ArrayBuffer {
    [Uint8Contents]: <30 82 02 fc 30 82 01 e4 a0 03 02 01 02 02 01 01 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 0f 31 0d 30 0b 06 03 55 04 03 13 04 54 65 73 74 30 1e 17 0d 31 39 31 32 33 31 32 31 30 30 30 30 5a 17 0d 32 30 30 31 30 31 32 31 30 30 30 30 5a 30 0f 31 0d 30 0b 06 03 55 04 03 13 04 54 65 73 74 30 82 01 ... 668 more bytes>,
    byteLength: 768
  },
  tbs: ArrayBuffer {
    [Uint8Contents]: <30 82 01 e4 a0 03 02 01 02 02 01 01 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 0f 31 0d 30 0b 06 03 55 04 03 13 04 54 65 73 74 30 1e 17 0d 31 39 31 32 33 31 32 31 30 30 30 30 5a 17 0d 32 30 30 31 30 31 32 31 30 30 30 30 5a 30 0f 31 0d 30 0b 06 03 55 04 03 13 04 54 65 73 74 30 82 01 22 30 0d 06 ... 388 more bytes>,
    byteLength: 488
  },
  serialNumber: '01',
  subject: 'CN=Test',
  issuer: 'CN=Test',
  signatureAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
  signature: ArrayBuffer {
    [Uint8Contents]: <2e 78 fb 4b f6 c8 a1 9d b4 d1 8b 22 80 20 c1 68 46 39 a6 11 d1 a9 7a 13 03 8d 1e 0e 5e 87 b5 33 2a ba 44 1b 96 6d 91 e7 fd c0 ce b7 93 fe e4 df d3 d0 57 7c 9a eb 7e 3e 8b ed c6 07 ad 80 df fd 8f f7 ce 26 07 db 0e 9f af e6 cb 70 02 2d 17 9f f5 c1 0d ef d6 cf 1d ec 78 a0 dd 5d 46 2a 60 08 71 74 2c 26 ... 156 more bytes>,
    byteLength: 256
  },
  notBefore: 2019-12-31T21:00:00.000Z,
  notAfter: 2020-01-01T21:00:00.000Z,
  extensions: Extensions(4) [
    BasicConstraintsExtension {
      rawData: [ArrayBuffer],
      type: '2.5.29.19',
      critical: true,
      value: [ArrayBuffer],
      ca: true,
      pathLength: 2
    },
    ExtendedKeyUsageExtension {
      rawData: [ArrayBuffer],
      type: '2.5.29.37',
      critical: true,
      value: [ArrayBuffer],
      usages: [ExtendedKeyUsage]
    },
    KeyUsagesExtension {
      rawData: [ArrayBuffer],
      type: '2.5.29.15',
      critical: true,
      value: [ArrayBuffer],
      usages: 96
    },
    SubjectKeyIdentifierExtension {
      rawData: [ArrayBuffer],
      type: '2.5.29.14',
      critical: false,
      value: [ArrayBuffer],
      keyId: 'f525754650a3dee83f8bd777ee3b53ecc2c8d726'
    }
  ],
  publicKey: PublicKey {
    rawData: ArrayBuffer {
      [Uint8Contents]: <30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 b6 f4 f1 cf dd 26 a1 23 45 b6 6e 4e ec 3e 20 8a 3f 90 ec 84 46 49 87 a2 05 c5 eb da ac 84 37 eb a3 bf 46 b5 8e 82 75 25 8a 80 19 10 79 13 c0 13 6c 29 df 56 44 1c ec f8 7b 34 0a f2 13 41 b5 53 98 e1 f5 ... 194 more bytes>,
      byteLength: 294
    },
    algorithm: {
      name: 'RSASSA-PKCS1-v1_5',
      publicExponent: [Uint8Array],
      modulusLength: 2048
    }
  }
}
```

### Verify a certificate

```js
const cert = new x509.X509Certificate(raw);
const issuer = new x509.X509Certificate(issuerRaw);

// Checks the signature and that the certificate is valid at `date` (default: now);
// pass `signatureOnly: true` to check only the signature.
const ok = await cert.verify({ date: new Date(), publicKey: issuer });
```

Pass the issuer certificate (or its `PublicKey`) as `publicKey`: x509 then imports the key with the hash of the certificate's signature algorithm. A `CryptoKey` is used as is, and `issuer.publicKey.export()` without arguments imports an RSA key with SHA-256, so it doesn't verify a certificate signed with, for example, `sha384WithRSAEncryption`. Export it with the matching algorithm instead: `issuer.publicKey.export({ name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, ["verify"])`.

### Build a certificate chain

```js
const chain = new x509.X509ChainBuilder({
  certificates: [
    new x509.X509Certificate(raw1),
    new x509.X509Certificate(raw2),
    // ...
    new x509.X509Certificate(rawN),
  ],
});

const cert = new x509.X509Certificate(raw);
const items = await chain.build(cert);
console.log(items); // [ X509Certificate, X509Certificate, X509Certificate ]
```

### Export a list of X509 certificates to PKCS#7 format

```js
const certs = new x509.X509Certificates([
  new x509.X509Certificate("MIIDljCCAn6gAwIBAgIOSETcxtRwD...S+kAFXIwugUGYEnTWp0m5bAn5NlD314IEOg4mnS8Q=="),
  new x509.X509Certificate("MIIDljCCAn6gAwIBAgIOSETcxtRwD...w8Y/o+hk3QzNBVa3ZUvzDhVAmamQflvw3lXMm/JG4U="),
]);

console.log(certs.export("base64")); // "MIICTAYJKoZIhvcNAQcCoIICPTCCAjkCAQAxADACBgCgggIq...F7EZPNo3pjbfznpIilRMRrmwf5dkgCdSKDdE94xAA==");
```
