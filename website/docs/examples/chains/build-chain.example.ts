import "reflect-metadata";
import * as x509 from "@peculiar/x509";

const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const notBefore = new Date("2026-01-01T00:00:00Z");
const notAfter = new Date("2036-01-01T00:00:00Z");

// Root CA
const rootKeys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
const root = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: "01",
  name: "CN=Example Root CA",
  notBefore,
  notAfter,
  signingAlgorithm: algorithm,
  keys: rootKeys,
  extensions: [
    new x509.BasicConstraintsExtension(true, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    await x509.SubjectKeyIdentifierExtension.create(rootKeys.publicKey),
  ],
});

// Intermediate CA, signed by the root
const intermediateKeys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
const intermediate = await x509.X509CertificateGenerator.create({
  serialNumber: "02",
  subject: "CN=Example Issuing CA",
  issuer: root.subject,
  notBefore,
  notAfter,
  publicKey: intermediateKeys.publicKey,
  signingKey: rootKeys.privateKey,
  signingAlgorithm: algorithm,
  extensions: [
    new x509.BasicConstraintsExtension(true, 0, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    await x509.SubjectKeyIdentifierExtension.create(intermediateKeys.publicKey),
    await x509.AuthorityKeyIdentifierExtension.create(root),
  ],
});

// End-entity certificate, signed by the intermediate
const leafKeys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
const leaf = await x509.X509CertificateGenerator.create({
  serialNumber: "03",
  subject: "CN=www.example.com",
  issuer: intermediate.subject,
  notBefore,
  notAfter,
  publicKey: leafKeys.publicKey,
  signingKey: intermediateKeys.privateKey,
  signingAlgorithm: algorithm,
  extensions: [await x509.AuthorityKeyIdentifierExtension.create(intermediate)],
});

// The builder searches the given certificates for each issuer, in any order,
// matching names and key identifiers and checking signatures
const builder = new x509.X509ChainBuilder({ certificates: [root, intermediate] });
const chain = await builder.build(leaf);
console.log("chain:", chain.map((cert) => cert.subject));

// The chain ends at a self-signed certificate if the root was found
const top = chain[chain.length - 1];
console.log("ends at a self-signed root:", await top.isSelfSigned());

// The builder doesn't decide trust: compare the last certificate with your trusted roots
const trustedThumbprint = new Uint8Array(await root.getThumbprint("SHA-256"));
const topThumbprint = new Uint8Array(await top.getThumbprint("SHA-256"));
console.log("trusted root:", topThumbprint.every((byte, i) => byte === trustedThumbprint[i]));

// Without the intermediate, the chain stops at the leaf
const partial = await new x509.X509ChainBuilder({ certificates: [root] }).build(leaf);
console.log("without the intermediate:", partial.map((cert) => cert.subject));
