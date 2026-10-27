---
sidebar_position: 0
sidebar_label: Overview
---

# Examples

Every example is a complete script. Copy it into your project, or press **Run** to execute it in your browser with the current version of @peculiar/x509. The examples use the platform's WebCrypto (`globalThis.crypto`), which browsers and Node.js 20+ provide.

## Certificates

- [Read a certificate](certificates/parse-certificate.mdx): subject, issuer, validity, public key, and typed extensions from a PEM file.
- [Create a self-signed certificate](certificates/self-signed.mdx): a CA certificate with Basic Constraints and Key Usage, exported as PEM.
- [Issue and verify a certificate](certificates/issue-certificate.mdx): a CA signs a server certificate, and `verify()` checks it against the issuer.
- [Distinguished names](certificates/names.mdx): parse, build, and read names in string and JSON form.

## Certificate requests

- [Create a certificate request](requests/create-csr.mdx): a PKCS#10 CSR with requested extensions and a challenge password.
- [Issue a certificate from a request](requests/sign-csr.mdx): verify a CSR and issue a certificate for its key.

## Revocation

- [Create and check a CRL](revocation/crl.mdx): revoke serial numbers with a reason, verify the CRL, and look up a certificate.

## Chains and bundles

- [Build a certificate chain](chains/build-chain.mdx): order certificates from a leaf up to its root.
- [PKCS#7 files and PEM bundles](chains/pkcs7.mdx): read and write `.p7b` files and lists of PEM certificates.
