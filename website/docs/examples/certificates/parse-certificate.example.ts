import "reflect-metadata";
import * as x509 from "@peculiar/x509";

// A TLS server certificate for www.example.com, issued by "Example Root CA"
const pem = `-----BEGIN CERTIFICATE-----
MIICEDCCAbagAwIBAgIIXzqcIeB7RNgwCgYIKoZIzj0EAwIwPTEYMBYGA1UEAxMP
RXhhbXBsZSBSb290IENBMRQwEgYDVQQKEwtFeGFtcGxlIE9yZzELMAkGA1UEBhMC
VVMwHhcNMjYwMTAxMDAwMDAwWhcNMjcwMTAxMDAwMDAwWjA9MRgwFgYDVQQDEw93
d3cuZXhhbXBsZS5jb20xFDASBgNVBAoTC0V4YW1wbGUgT3JnMQswCQYDVQQGEwJV
UzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGISS+ND1oThW3Ke/JkyECZRC6+R
nzT3l0z30BXye50uzdidSuCL0vWu/s3mU5kRDjM+3MuR3+HErbzgZJNxIKqjgZ8w
gZwwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwJwYDVR0RBCAwHoIPd3d3LmV4YW1wbGUuY29tggtleGFtcGxlLmNvbTAd
BgNVHQ4EFgQUAYDauPaM+5A4BQshHhNMjaTK3M8wHwYDVR0jBBgwFoAUNTf5oo+G
jsQ+pYY1LpN86FR89DEwCgYIKoZIzj0EAwIDSAAwRQIgL1IzTqALvBCd9He8SFXD
/tPMx8glYA2diQmSNLatff4CIQCtUTVx6CgmpWIFXGHkEjZD5DcFl3DBHXQsIAmA
t74Wgg==
-----END CERTIFICATE-----`;

// PEM, Base64, hex and DER bytes are all accepted
const cert = new x509.X509Certificate(pem);

console.log("subject:", cert.subject);
console.log("issuer:", cert.issuer);
console.log("serial:", cert.serialNumber);
console.log("valid from:", cert.notBefore.toISOString());
console.log("valid to:", cert.notAfter.toISOString());
console.log("signature algorithm:", cert.signatureAlgorithm);
console.log("public key:", cert.publicKey.algorithm);

// Individual name attributes
console.log("common name:", cert.subjectName.getField("CN"));

// Typed access to extensions
const san = cert.getExtension(x509.SubjectAlternativeNameExtension);
console.log("DNS names:", san?.names.items.filter((name) => name.type === "dns").map((name) => name.value));

const basicConstraints = cert.getExtension(x509.BasicConstraintsExtension);
console.log("is a CA:", basicConstraints?.ca ?? false);

const keyUsage = cert.getExtension(x509.KeyUsagesExtension);
console.log("can sign:", Boolean(keyUsage && keyUsage.usages & x509.KeyUsageFlags.digitalSignature));

const extendedKeyUsage = cert.getExtension(x509.ExtendedKeyUsageExtension);
console.log("TLS server:", extendedKeyUsage?.usages.includes(x509.ExtendedKeyUsage.serverAuth) ?? false);

// SHA-256 fingerprint
const thumbprint = await cert.getThumbprint("SHA-256");
console.log("SHA-256:", Array.from(new Uint8Array(thumbprint), (byte) => byte.toString(16).padStart(2, "0")).join(":"));

// Everything at once, in a readable form
console.log(cert.toString("text"));
