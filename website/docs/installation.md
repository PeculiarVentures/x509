# Installation

Run one of the following commands to add `@peculiar/x509` and a Reflect polyfill to your project:

```bash npm2yarn
npm install @peculiar/x509 reflect-metadata
```

## Requirements

@peculiar/x509 is an ES module and runs in modern browsers and in Node.js `^20.19.0 || >=22.12.0`. On these Node.js versions, CommonJS code can still load it with `require("@peculiar/x509")`.

If you compile TypeScript to CommonJS, set `"module"` to `"node20"` or `"nodenext"` in `tsconfig.json`.

### Reflect polyfill

The library registers its algorithms with [tsyringe](https://github.com/microsoft/tsyringe), which needs a Reflect polyfill. Import one before `@peculiar/x509`, once, at the top of your entry point:

```ts
import "reflect-metadata";
import * as x509 from "@peculiar/x509";
```

[core-js](https://www.npmjs.com/package/core-js) (`core-js/full/reflect`) and [@abraham/reflection](https://www.npmjs.com/package/@abraham/reflection) work too. Without a polyfill, the import fails with "tsyringe requires a reflect polyfill".

### Crypto provider

Signing, verification and hashing use WebCrypto. By default the library uses `globalThis.crypto`, which browsers and Node.js provide. To use another implementation, for example [@peculiar/webcrypto](https://www.npmjs.com/package/@peculiar/webcrypto) 2.x for algorithms your platform lacks, set it as the provider:

```ts
import { Crypto } from "@peculiar/webcrypto";

x509.cryptoProvider.set(new Crypto());
```

Most methods also take a `crypto` argument that overrides the provider for one call.

### Browsers

Bundle the package with your app (Vite, webpack, esbuild, Rollup), or load the ESM build from a CDN that serves npm packages as browser modules, such as [esm.sh](https://esm.sh):

```html
<script type="module">
  import "https://esm.sh/reflect-metadata";
  import * as x509 from "https://esm.sh/@peculiar/x509@3";

  const cert = new x509.X509Certificate(pem);
  console.log(cert.subject);
</script>
```

Pin the version in the URL, and prefer bundling or hosting your own copy in production.

## First steps

Create a self-signed certificate and read it back:

```ts
import "reflect-metadata";
import * as x509 from "@peculiar/x509";

const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const keys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);

const cert = await x509.X509CertificateGenerator.createSelfSigned({
  name: "CN=Example",
  keys,
  signingAlgorithm: algorithm,
});

const pem = cert.toString("pem");
console.log(new x509.X509Certificate(pem).subject); // CN=Example
```

Next, browse the [examples](examples/index.md) or the [API reference](api/index.md).

## Upgrading from v2

v3 is ESM-only, raises the minimum Node.js version, and moves to `@peculiar/asn1-schema` 3 as a peer dependency. The public API is unchanged. Read the [breaking changes](https://github.com/PeculiarVentures/x509#breaking-changes-in-v3) before upgrading, and upgrade other libraries built on `@peculiar/asn1-schema` at the same time.
