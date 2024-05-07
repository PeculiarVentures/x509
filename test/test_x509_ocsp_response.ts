import {OCSPResponseCreateParams} from "../src/ocsp";
import {OCSPResponseGenerator} from "../src/ocsp";
import {SingleResponseInterface} from "../src/ocsp";
import { NonceExtension } from "../src/extensions";

import * as x509 from "../src";
import * as assert from "assert";
import { Crypto } from "@peculiar/webcrypto";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

const alg = {
    name: "ECDSA",
    hash: "SHA-1",
    namedCurve: "P-256",
};

const pemLeaf = `-----BEGIN CERTIFICATE-----
MIIGGDCCBZ2gAwIBAgITMwAABF8rDWWdcXI+fQAAAAAEXzAKBggqhkjOPQQDAzBd
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS4w
LAYDVQQDEyVNaWNyb3NvZnQgQXp1cmUgRUNDIFRMUyBJc3N1aW5nIENBIDA4MB4X
DTI0MDEzMDAyMTUyNFoXDTI1MDEyNDAyMTUyNFowajELMAkGA1UEBhMCVVMxCzAJ
BgNVBAgTAldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
Q29ycG9yYXRpb24xHDAaBgNVBAMTE2xlYXJuLm1pY3Jvc29mdC5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQD5AJSeo8MVxxZXh4eCMmV3Yfbrc19Fd0REslo
cnHRDmrq6IFvYRwC0pqR/xjELJiAP+WF1Obdg7xAnhd7GmESo4IELTCCBCkwggF9
BgorBgEEAdZ5AgQCBIIBbQSCAWkBZwB1AM8RVu7VLnyv84db2Wkum+kacWdKsBfs
rAHSW3fOzDsIAAABjVgvj+0AAAQDAEYwRAIgY2PzrG1ChzV4szR6fE1xFPHP6vLS
aShFsYbJkSkjlLoCIFb6oNcpWWuzK20MJvoJwNZYUl7n/bsX0AzIpoEhMaKYAHYA
fVkeEuF4KnscYWd8Xv340IdcFKBOlZ65Ay/ZDowuebgAAAGNWC+Q1AAABAMARzBF
AiEArps9RATMRAKj4WpKwNb+mPVAVPRv5Ir8iR1GnftpNioCIGNi+EyPvdc6iB9R
/lnV1wTpgKeHRJcdisZepdXbVuVLAHYAVYHUwhaQNgFK6gubVzxT8MDkOHhwJQgX
L6OqHQcT0wwAAAGNWC+QwgAABAMARzBFAiEA+W72vqC7fR2Ko0R7TGh7ue0I/Si/
mG69h128xewl6QICICPU53lockSfHEn++TospCqyM/EcRlx87UuvrX17t9zVMCcG
CSsGAQQBgjcVCgQaMBgwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwEwPAYJKwYBBAGC
NxUHBC8wLQYlKwYBBAGCNxUIh73XG4Hn60aCgZ0ujtAMh/DaHV2ChOVpgvOnPgIB
ZAIBJjCBtAYIKwYBBQUHAQEEgacwgaQwcwYIKwYBBQUHMAKGZ2h0dHA6Ly93d3cu
bWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwQXp1cmUlMjBF
Q0MlMjBUTFMlMjBJc3N1aW5nJTIwQ0ElMjAwOCUyMC0lMjB4c2lnbi5jcnQwLQYI
KwYBBQUHMAGGIWh0dHA6Ly9vbmVvY3NwLm1pY3Jvc29mdC5jb20vb2NzcDAdBgNV
HQ4EFgQURohnyebpes3pcn7gdTIKBunVj24wDgYDVR0PAQH/BAQDAgeAMDcGA1Ud
EQQwMC6CF3d3dy5sZWFybi5taWNyb3NvZnQuY29tghNsZWFybi5taWNyb3NvZnQu
Y29tMAwGA1UdEwEB/wQCMAAwagYDVR0fBGMwYTBfoF2gW4ZZaHR0cDovL3d3dy5t
aWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwQXp1cmUlMjBFQ0Ml
MjBUTFMlMjBJc3N1aW5nJTIwQ0ElMjAwOC5jcmwwZgYDVR0gBF8wXTBRBgwrBgEE
AYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
L3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMAgGBmeBDAECAjAfBgNVHSMEGDAW
gBStVB0DVHHGL17WWxhYzm4kxdaiCjAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB
BQUHAwEwCgYIKoZIzj0EAwMDaQAwZgIxAPcv4LizT5USJJ9KeCV4z1DGq4R56VE7
Dj1HYgkk45BSrXAQZaMy9wOBl414Gyev2gIxAIGGiBW4YvWldD5BkIatfX8DkP1L
mtIXPcp+B0BYlDTzyaMOp9xtno+ZJgYXvSRrYg==
-----END CERTIFICATE-----`;

  const pemCA = `-----BEGIN CERTIFICATE-----
MIIDXDCCAuOgAwIBAgIQDvLl2DaBUgJV6Sxgj7wv9DAKBggqhkjOPQQDAzBhMQsw
CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
ZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMzAe
Fw0yMzA2MDgwMDAwMDBaFw0yNjA4MjUyMzU5NTlaMF0xCzAJBgNVBAYTAlVTMR4w
HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLjAsBgNVBAMTJU1pY3Jvc29m
dCBBenVyZSBFQ0MgVExTIElzc3VpbmcgQ0EgMDgwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATlQzoKIJQIe8bd4sX2x9XBtFvoh5m7Neph3MYORvv/rg2Ew7Cfb00eZ+zS
njUosyOUCspenehe0PyKtmq6pPshLu5Ww/hLEoQT3drwxZ5PaYHmGEGoy2aPBeXa
23k5ruijggFiMIIBXjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBStVB0D
VHHGL17WWxhYzm4kxdaiCjAfBgNVHSMEGDAWgBSz20ik+aHF2K42QcwRY2liKbxL
xjAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
cnQuY29tMEAGCCsGAQUFBzAChjRodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
RGlnaUNlcnRHbG9iYWxSb290RzMuY3J0MEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6
Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMy5jcmwwHQYD
VR0gBBYwFDAIBgZngQwBAgEwCAYGZ4EMAQICMAoGCCqGSM49BAMDA2cAMGQCMD+q
5Uq1fSGZSKRhrnWKKXlp4DvfZCEU/MF3rbdwAaXI/KVM65YRO9HvRbfDpV3x1wIw
CHvqqpg/8YJPDn8NJIS/Rg+lYraOseXeuNYzkjeY6RLxIDB+nLVDs9QJ3/co89Cd
-----END CERTIFICATE-----`;

const pemSigning = `-----BEGIN CERTIFICATE-----
MIICgDCCAgagAwIBAgITMwAAExoZB42E3cpifgAAAAATGjAKBggqhkjOPQQDAzBd
MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS4w
LAYDVQQDEyVNaWNyb3NvZnQgQXp1cmUgRUNDIFRMUyBJc3N1aW5nIENBIDA4MB4X
DTI0MDQyNzE1NTAyOVoXDTI0MDUyNzE1NTAyOVowHzEdMBsGA1UEAxMUQXp1cmVF
Q0MwOCBPQ1NQIENlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQp91EZCvSf
zcJxVq1nPS+M8FFLD1lbqDeB+7ffSxGA41VKBNOBtmeFcO0qdoX4moUsChZaKrpt
lb+GH3U/d3ipo4HiMIHfMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBMG
A1UdJQQMMAoGCCsGAQUFBwMJMB0GA1UdDgQWBBRiVhX2B3hJ09it0w2ks64AfDqe
WTAfBgNVHSMEGDAWgBStVB0DVHHGL17WWxhYzm4kxdaiCjA8BgkrBgEEAYI3FQcE
LzAtBiUrBgEEAYI3FQiHvdcbgefrRoKBnS6O0AyH8NodXYPZ1yKB9N4fAgFkAgEX
MBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwkwDwYJKwYBBQUHMAEFBAIFADAK
BggqhkjOPQQDAwNoADBlAjBv1c+46GRbmZENdVaHVNGDF0yx5ZCOLOVA8el0GzwT
vH3TWSI8I4Aut2/r2BXQd1ACMQDLGW3LKT7YtMHyxkvatoDsLp0EeTjVTE6hsWX4
f/deM4VHt8ZHvUZibX0pSq9U/ac=
-----END CERTIFICATE-----`;

const leafPrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgM5McsRyvuC8+aFYwu2ci0Qh8bolc3kWCiF7F1WAQH1ahRANCAAS6zcN8ZmKsXlSR1FAPtooB6nGmsbNVNbkT2tNF6EDcAveJnd5xhNFtZ5dvPY6SR1Jjp/oytNlNFYXUrryrLfCJ";
const leafPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEus3DfGZirF5UkdRQD7aKAepxprGzVTW5E9rTRehA3AL3iZ3ecYTRbWeXbz2OkkdSY6f6MrTZTRWF1K68qy3wiQ==";
const caPrivateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgE/+gM0YVMwVMLEJZRlTnFHjQdA7PGlvx4RrwbNjWvEChRANCAAT9AozzW2pwptkjuponmuLdwEdnpTKNdrzQt0UxC7/GtA4rdy6xl9w8FtuN1rbeDo3b6EkYv/jtbsU3yL+0oQ1o";
const caPublicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/QKM81tqcKbZI7qaJ5ri3cBHZ6UyjXa80LdFMQu/xrQOK3cusZfcPBbbjda23g6N2+hJGL/47W7FN8i/tKENaA==";

context("OCSP", async () => {

  const CAIssuerVector = {
        serialNumber: "00",
        name: "CN=CA, O=Дом",
        subject: "CN=CA, O=Дом",
        issuer: "CN=CA, O=Дом",
        notBefore: new Date(Date.UTC(2020, 0, 1, 8, 0, 0)), // UTCTime 2020-01-01 08:00:00 UTC
        notAfter: new Date(Date.UTC(2040, 0, 2, 8, 0, 0)),  // UTCTime 2040-01-02 08:00:00 UTC
        signingAlgorithm: alg,
        extensions: [
          new x509.BasicConstraintsExtension(true, 2, true),
          new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
          new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
          new x509.CertificatePolicyExtension([
            "1.2.3.4.5",
            "1.2.3.4.5.6",
            "1.2.3.4.5.6.7",
          ]),
        ]
      };

  const LeafVector = {
    serialNumber: "01",
    name: "CN=Test, O=Дом",
    subject: "CN=Test, O=Дом",
    issuer: "CN=CA, O=Дом",
    notBefore: new Date(Date.UTC(2020, 0, 1, 8, 0, 0)), // UTCTime 2020-01-01 08:00:00 UTC
    notAfter: new Date(Date.UTC(2040, 0, 2, 8, 0, 0)),  // UTCTime 2040-01-02 08:00:00 UTC
    signingAlgorithm: alg,
    extensions: [
      new x509.BasicConstraintsExtension(true, 2, true),
      new x509.ExtendedKeyUsageExtension(["1.2.3.4.5.6.7", "2.3.4.5.6.7.8"], true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      new x509.CertificatePolicyExtension([
        "1.2.3.4.5",
        "1.2.3.4.5.6",
        "1.2.3.4.5.6.7",
      ]),
    ]
  };



  it("generating an OCSP response", async () => {

    const keysCA = {
      publicKey: await crypto.subtle.importKey("spki", Buffer.from(caPublicKey, "base64"), alg, true, ["verify"]),
      privateKey: await crypto.subtle.importKey("pkcs8", Buffer.from(caPrivateKey, "base64"), alg, true, ["sign"]),
    };

    const keysLeaf = {
      publicKey: await crypto.subtle.importKey("spki", Buffer.from(leafPublicKey, "base64"), alg, true, ["verify"]),
      privateKey: await crypto.subtle.importKey("pkcs8", Buffer.from(leafPrivateKey, "base64"), alg, true, ["sign"]),
    };

    assert.ok(keysCA.publicKey);
    assert.ok(keysCA.privateKey);
    const CACert = await x509.X509CertificateGenerator.createSelfSigned({
      keys: keysCA,

      ...CAIssuerVector,
    });

    const leafCert = await x509.X509CertificateGenerator.create({
      publicKey: keysLeaf.publicKey,
      signingKey: keysCA.privateKey,


      ...LeafVector,
    });

    // create OCSPResponseCreateParams object and fill it with data
    const singleResponse: SingleResponseInterface ={
      issuer: CACert,
      certificate: leafCert,
      thisUpdate: new Date(Date.UTC(2024, 0, 1, 8, 0, 0)),
      nextUpdate: new Date(Date.UTC(2025, 0, 1, 8, 0, 0)),
      extensions : [],
      status: 0,
    };

    const ocspRequestParams: OCSPResponseCreateParams = {
      /**
       * Response signature algorithm
       */
      signatureAlgorithm: "SHA-1",
      /**
       * Response signing key
       */
      signingKey: keysCA.privateKey,
      /**
       * The OCSP request for which the response is being generated
       */
      singleResponses: [singleResponse],
      /**
       * The certificate that will be used to sign the response
       */
      responderCertificate: CACert,
      /**
       * List of certificates that can be used to verify the signature of the response
       */
      certificates: [CACert],
      /**
       * The date and time for which the status of the certificate is issued
       * The default is the current time
       */
      date: new Date(Date.UTC(2020, 0, 1, 8, 0, 0)),
      /**
       * Certificate status
       * The default is successful
       */
      status: 0,
      /**
       * List of response extensions
       */
      extensions: [new NonceExtension(new TextEncoder().encode("Test Nonce"))],
    };

  const response = await OCSPResponseGenerator.create(ocspRequestParams);
  assert.ok(await response.verify(keysCA.publicKey));
  // console.log(response.toString());
  });
});