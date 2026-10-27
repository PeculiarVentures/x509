import "reflect-metadata";
import * as x509 from "@peculiar/x509";

const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };

// The CA that issues the CRL. Its key usage includes cRLSign.
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
  ],
});

// Revoke two certificates by serial number
const created = await x509.X509CrlGenerator.create({
  issuer: caCert.subject,
  thisUpdate: new Date("2026-03-01T00:00:00Z"),
  nextUpdate: new Date("2026-03-08T00:00:00Z"),
  entries: [
    {
      serialNumber: "5f3a9c21e07b44d8",
      revocationDate: new Date("2026-02-15T10:00:00Z"),
      reason: x509.X509CrlReason.keyCompromise,
      // When the key is known or suspected to have been compromised
      invalidity: new Date("2026-02-14T00:00:00Z"),
    },
    {
      serialNumber: "0a1b2c3d4e5f",
      revocationDate: new Date("2026-02-20T00:00:00Z"),
      reason: x509.X509CrlReason.superseded,
    },
  ],
  signingAlgorithm: algorithm,
  signingKey: caKeys.privateKey,
});
const pem = created.toString("pem");
console.log(pem);

// A relying party: parse the CRL and check it was signed by the CA
const crl = new x509.X509Crl(pem);
console.log("issuer:", crl.issuer);
console.log("signed by the CA:", await crl.verify({ publicKey: caCert }));
console.log("next update:", crl.nextUpdate?.toISOString());

for (const entry of crl.entries) {
  console.log(
    "revoked:",
    entry.serialNumber,
    entry.revocationDate.toISOString(),
    entry.reason === undefined ? "no reason" : x509.X509CrlReason[entry.reason],
  );
}

// Look up a serial number, or pass an X509Certificate
const revoked = crl.findRevoked("5f3a9c21e07b44d8");
console.log("5f3a9c21e07b44d8 revoked:", revoked !== null, revoked?.invalidity?.toISOString());
console.log("1234 revoked:", crl.findRevoked("1234") !== null);
