import "reflect-metadata";
import * as x509 from "@peculiar/x509";

// The applicant's key pair. The private key never leaves the applicant.
const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
const keys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);

const csr = await x509.Pkcs10CertificateRequestGenerator.create({
  name: "CN=www.example.com, O=Example Org, C=US",
  keys,
  signingAlgorithm: algorithm,
  // Extensions the applicant asks the CA to include
  extensions: [
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature),
    new x509.SubjectAlternativeNameExtension([
      { type: "dns", value: "www.example.com" },
      { type: "dns", value: "example.com" },
    ]),
  ],
  attributes: [new x509.ChallengePasswordAttribute("password")],
});

// Send this to the CA
console.log(csr.toString("pem"));

// The request is signed with the applicant's private key, which proves possession of the key
console.log("signature valid:", await csr.verify());
console.log("subject:", csr.subject);

// Requested extensions come back as typed objects
for (const extension of csr.extensions) {
  if (extension instanceof x509.SubjectAlternativeNameExtension) {
    console.log("requested names:", extension.names.toJSON());
  }
}
