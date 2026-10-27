import "reflect-metadata";
import * as x509 from "@peculiar/x509";

const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const validity = { notBefore: new Date("2026-01-01T00:00:00Z"), notAfter: new Date("2036-01-01T00:00:00Z") };
const rootKeys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
const issuerKeys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
const signerKeys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);

const root = await x509.X509CertificateGenerator.createSelfSigned({
  ...validity,
  serialNumber: "01",
  name: "CN=Manufacturer Root",
  keys: rootKeys,
  signingAlgorithm: algorithm,
  extensions: [new x509.BasicConstraintsExtension(true)],
});

const card = await x509.X509CertificateGenerator.create({
  ...validity,
  serialNumber: "02",
  subject: "CN=Manufacturer Card",
  issuer: root.subject,
  publicKey: issuerKeys.publicKey,
  signingKey: rootKeys.privateKey,
  signingAlgorithm: algorithm,
  extensions: [new x509.BasicConstraintsExtension(true)],
});

const signer = await x509.X509CertificateGenerator.create({
  ...validity,
  serialNumber: "03",
  subject: "CN=Partition",
  issuer: card.subject,
  publicKey: signerKeys.publicKey,
  signingKey: issuerKeys.privateKey,
  signingAlgorithm: algorithm,
});

// Corrupt only the card's signature. Its key still verifies the partition.
// Decreasing a trailing signature byte makes this copy sort before the original.
const damagedBytes = new Uint8Array(card.rawData.slice(0));
let index = damagedBytes.length - 1;
while (!damagedBytes[index]) index--;
damagedBytes[index]--;
const damagedCard = new x509.X509Certificate(damagedBytes);

const builder = new x509.X509ChainBuilder({ certificates: [damagedCard, card] });
const path = await builder.buildToAnchor(signer, {
  trustAnchors: root, // Included automatically; no need to repeat it in certificates.
  limits: { maxDepth: 8, maxSearchSteps: 1_000 },
});
console.log("signer → anchor:", path.map((cert) => cert.subject));
console.log("used the original card:", path[1] === card);
console.log("anchor → signer:", [...path].reverse().map((cert) => cert.subject));

// Failure is explicit: no partial path is returned.
try {
  await builder.buildToAnchor(signer, { trustAnchors: root, limits: { maxDepth: 2 } });
} catch (error) {
  if (!(error instanceof x509.X509ChainBuildError)) throw error;
  console.log("search outcome:", error.code, error.limit);
  console.log("rejections:", error.rejections.map((event) => event.reason));
}
