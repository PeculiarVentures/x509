# @peculiar/x509

![Node.js CI](https://github.com/PeculiarVentures/x509/workflows/Node.js%20CI/badge.svg)

- [About](#about)
- [Installation](#installation)
- [Usage](#usage)
  - [Create a self-signed certificate](#create-a-self-signed-certificate)
  - [Parse a X509 certificate](#parse-a-x509-certificate)
  - [Create a PKCS#10 certificate request](#create-a-pkcs10-certificate-request)
  - [Inspected a X509 certificate object](#inspected-a-x509-certificate-object)
  - [Build a certificate chain](#build-a-certificate-chain)
  - [Export a list of X509 certificates to PKCS#7 format](#export-a-list-of-x509-certificates-to-pkcs7-format)

## About

`@peculiar/x509` is an easy to use TypeScript/Javascript library based on `@peculiar/asn1-schema` that makes generating X.509 Certificates and Certificate Requests as well as validating certificate chains easy.

## Installation

```
npm install @peculiar/x509
```

## Usage

### Create a self-signed certificate
```js
import * as x509 from "@peculiar/x509";

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
  ]
});
```

### Parse a x509 certificate
```js
import * as x509 from "@peculiar/x509";

const base64 = "MIIDljCCAn6gAwIBAgIOSETcxtRwD...S+kAFXIwugUGYEnTWp0m5bAn5NlD314IEOg4mnS8Q==";
const raw = Buffer.from(base64, "base64");

const cert = new x509.X509Certificate(raw);
console.log(cert.subject); // CN=Test, O=PeculiarVentures LLC
```

### Create a PKCS#10 certificate request
```js
import * as x509 from "@peculiar/x509";

const alg = {
  name: "ECDSA",
  namedCurve: "P-384",
  hash: "SHA-384",
}
const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
const csr = await x509.Pkcs10CertificateRequestGenerator.create({
  name: "CN=Test",
  keys,
  signingAlgorithm: alg,
  extensions: [
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment),
  ],
  attributes: [
    new x509.ChallengePasswordAttribute("password"),
  ]
});
```

### Inspected a X509 certificate object
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

### Build a certificate chain
```js
import * as x509 from "@peculiar/x509";

const chain = new x509.X509ChainBuilder({
  certificates: [
    new x509.X509Certificate(raw1),
    new x509.X509Certificate(raw2),
    // ...
    new x509.X509Certificate(rawN),
  ],
});

const cert = x509.X509Certificate(raw);
const items = await chain.build(cert);
console.log(items); // [ X509Certificate, X509Certificate, X509Certificate ]
```

### Export a list of X509 certificates to PKCS#7 format
```js
import * as x509 from "@peculiar/x509";

const certs = new x509.X509Certificates([
  new x509.X509Certificate(Buffer.from("MIIDljCCAn6gAwIBAgIOSETcxtRwD...S+kAFXIwugUGYEnTWp0m5bAn5NlD314IEOg4mnS8Q==", "base64")),
  new x509.X509Certificate(Buffer.from("MIIDljCCAn6gAwIBAgIOSETcxtRwD...w8Y/o+hk3QzNBVa3ZUvzDhVAmamQflvw3lXMm/JG4U=", "base64")),
]);

const base64 = Buffer.from(await cert.export()).toString("base64");
console.log(base64); // "MIICTAYJKoZIhvcNAQcCoIICPTCCAjkCAQAxADACBgCgggIq...F7EZPNo3pjbfznpIilRMRrmwf5dkgCdSKDdE94xAA==");
```
