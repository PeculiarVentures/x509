import "reflect-metadata";
import * as x509 from "@peculiar/x509";

const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };

// The CA: a self-signed certificate and its key pair
const caKeys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
const caCert = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: "01",
  name: "CN=Example Root CA",
  notBefore: new Date("2026-01-01T00:00:00Z"),
  notAfter: new Date("2036-01-01T00:00:00Z"),
  signingAlgorithm: algorithm,
  keys: caKeys,
  extensions: [
    new x509.BasicConstraintsExtension(true, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
  ],
});

// The server's own key pair. Only its public key goes into the certificate.
const serverKeys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);

const serverCert = await x509.X509CertificateGenerator.create({
  serialNumber: "5f3a9c21e07b44d8",
  subject: "CN=www.example.com",
  issuer: caCert.subject,
  notBefore: new Date("2026-01-01T00:00:00Z"),
  notAfter: new Date("2027-01-01T00:00:00Z"),
  publicKey: serverKeys.publicKey,
  signingKey: caKeys.privateKey,
  signingAlgorithm: algorithm,
  extensions: [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
    new x509.SubjectAlternativeNameExtension([
      { type: "dns", value: "www.example.com" },
      { type: "dns", value: "example.com" },
    ]),
    await x509.SubjectKeyIdentifierExtension.create(serverKeys.publicKey),
    // Links the certificate to the CA key that signed it
    await x509.AuthorityKeyIdentifierExtension.create(caCert),
  ],
});

console.log(serverCert.toString("pem"));

// Pass the issuer certificate as `publicKey`. `verify()` checks the signature and,
// unless `signatureOnly` is set, that `date` (default: now) is within the validity period.
console.log("valid in 2026:", await serverCert.verify({ publicKey: caCert, date: new Date("2026-06-01T00:00:00Z") }));
console.log("valid in 2028:", await serverCert.verify({ publicKey: caCert, date: new Date("2028-01-01T00:00:00Z") }));

// A certificate signed by another key fails
const otherKeys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
console.log("signed by another key:", await serverCert.verify({ publicKey: otherKeys.publicKey, signatureOnly: true }));
