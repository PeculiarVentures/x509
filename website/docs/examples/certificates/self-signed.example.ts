import "reflect-metadata";
import * as x509 from "@peculiar/x509";

// The key algorithm doubles as the signing algorithm: ECDSA P-256 with SHA-256
const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const keys = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);

const cert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: "01",
  name: "CN=Example Root CA, O=Example Org, C=US",
  notBefore: new Date("2026-01-01T00:00:00Z"),
  notAfter: new Date("2036-01-01T00:00:00Z"),
  signingAlgorithm: algorithm,
  keys,
  extensions: [
    // A CA certificate that can issue certificates and CRLs
    new x509.BasicConstraintsExtension(true, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
  ],
});

console.log("self-signed:", await cert.isSelfSigned());
console.log("signature valid:", await cert.verify({ signatureOnly: true }));

// PEM for files; "base64", "base64url" and "hex" are also available, and `rawData` holds the DER bytes
console.log(cert.toString("pem"));

// Keep the private key to issue certificates later, for example as PKCS#8
const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);
console.log(x509.PemConverter.encode(pkcs8, "PRIVATE KEY"));
