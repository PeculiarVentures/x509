import "reflect-metadata";
import * as x509 from "@peculiar/x509";

const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };

async function createCertificate(name: string) {
  const keys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
  return x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name,
    notBefore: new Date("2026-01-01T00:00:00Z"),
    notAfter: new Date("2036-01-01T00:00:00Z"),
    signingAlgorithm: algorithm,
    keys,
  });
}

const certs = new x509.X509Certificates([
  await createCertificate("CN=First"),
  await createCertificate("CN=Second"),
]);

// A certs-only PKCS#7 (.p7b) file: PEM (with a "CMS" label), or "raw" for DER bytes
const p7b = certs.export("pem");
console.log(p7b);

// Read it back
const imported = new x509.X509Certificates(p7b);
console.log("from PKCS#7:", imported.map((cert) => cert.subject));

// A PEM bundle, such as a CA bundle or a server's chain file, holds several PEM blocks.
// PemConverter.decode() returns the DER bytes of each one.
const bundle = certs.map((cert) => cert.toString("pem")).join("\n");
const fromBundle = new x509.X509Certificates(x509.PemConverter.decode(bundle).map((der) => new x509.X509Certificate(der)));
console.log("from a PEM bundle:", fromBundle.map((cert) => cert.subject));

// X509Certificates is an Array, so filter() and find() work as usual
console.log("find:", fromBundle.find((cert) => cert.subject === "CN=Second")?.serialNumber);
