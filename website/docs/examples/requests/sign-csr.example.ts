import "reflect-metadata";
import * as x509 from "@peculiar/x509";

const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };

// Applicant: create a request (see "Create a certificate request")
const applicantKeys = await crypto.subtle.generateKey(algorithm, false, ["sign", "verify"]);
const request = await x509.Pkcs10CertificateRequestGenerator.create({
  name: "CN=www.example.com",
  keys: applicantKeys,
  signingAlgorithm: algorithm,
  extensions: [new x509.SubjectAlternativeNameExtension([{ type: "dns", value: "www.example.com" }])],
});
const pem = request.toString("pem");

// CA: its certificate and key pair
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

// CA: parse the request and check its signature before trusting anything in it
const csr = new x509.Pkcs10CertificateRequest(pem);
if (!(await csr.verify())) {
  throw new Error("Invalid certificate request signature");
}

// CA: decide which requested extensions to copy. Here only the subject alternative names.
const san = csr.extensions.find((extension) => extension instanceof x509.SubjectAlternativeNameExtension);

const cert = await x509.X509CertificateGenerator.create({
  serialNumber: "0a1b2c3d4e5f",
  subject: csr.subject,
  issuer: caCert.subject,
  notBefore: new Date("2026-01-01T00:00:00Z"),
  notAfter: new Date("2027-01-01T00:00:00Z"),
  publicKey: csr.publicKey,
  signingKey: caKeys.privateKey,
  signingAlgorithm: algorithm,
  extensions: [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
    ...(san ? [san] : []),
    await x509.AuthorityKeyIdentifierExtension.create(caCert),
  ],
});

console.log(cert.toString("pem"));
console.log("subject:", cert.subject);
console.log("issuer:", cert.issuer);
console.log("names:", cert.getExtension(x509.SubjectAlternativeNameExtension)?.names.toJSON());
console.log("issued by the CA:", await cert.verify({ publicKey: caCert, date: new Date("2026-06-01T00:00:00Z") }));
