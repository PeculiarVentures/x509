import * as assert from "assert";
import * as x509 from "../src";
import { AuthorityInformationAccessExtension } from "../src/extensions";
import { OCSPResponse } from "../src/ocsp";
import { Crypto } from "@peculiar/webcrypto";

const crypto = new Crypto();
x509.cryptoProvider.set(crypto);

context("OCSP", async () => {

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

  it("generating an OCSP request", async () => {
    const certificate = new x509.X509Certificate(pemLeaf);
    const issuer = new x509.X509Certificate(pemCA);


    // find extension with type  = "1.3.6.1.5.5.7.1.1"
    const authInfoAccess = certificate.extensions.find(obj => obj.type === "1.3.6.1.5.5.7.1.1") as AuthorityInformationAccessExtension;
    if(!authInfoAccess) throw new Error("No Authority Information Access extension found");


    // find OCSP URL and CA Issuers URL

    const ocspURL = authInfoAccess.getOcsp()[0];
    const caIssuers = authInfoAccess.getCaIssuers()[0];
    assert.ok(caIssuers);

    if(!ocspURL) throw new Error("No OCSP URL found in Authority Information Access extension");

    // generate Signing keys
    const alg = {
      name: "ECDSA",
      hash: {name: "SHA-1"},
      namedCurve: "P-256",
    };
    const keysCA = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);

    const request = await x509.ocsp.OCSPRequestGenerator.create({
      certificate,
      issuer,
      signingKey: keysCA.privateKey,
      signatureAlgorithm: alg,
    });
    assert.ok(request);

    const postRequest = request.rawData;

    // Send get request to OCSP server with the generated OCSP request
    const response = await fetch(ocspURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/ocsp-request",
      },
      body: postRequest,
    });

    assert(response.ok, "OCSP request failed");

    const data = await response.arrayBuffer();
    // console.log(data, "hex"); // Logs the ArrayBuffer as a Uint8Array for readability

    // Parse the OCSP response
    const ocspResponse = new OCSPResponse(data);
    // console.log(ocspResponse.toString());
    // extract certificate from ocspResponse
    if(ocspResponse.basicResponse) {
      const cert = ocspResponse.basicResponse.certificates[0];
      assert.ok(await ocspResponse.verify(cert));
    }
    assert.equal(ocspResponse.status, 0, "OCSP response is malformed");
  });
});