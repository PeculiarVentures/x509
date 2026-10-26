import { describe, it, expect } from "vitest";
import { X509Certificate } from "./index";
import { Convert } from "pvtsutils";
import * as x509 from "./index";

describe("X509Certificate", () => {
  const certWithSpecialEcParam = [
    "-----BEGIN CERTIFICATE-----",
    "MIIDQzCCAuugAwIBAgICARYwCQYHKoZIzj0EATCBjjELMAkGA1UEBhMCUlUxDzAN",
    "BgNVBAgTBlJ1c3NpYTEPMA0GA1UEBxMGTW9zY293MRcwFQYDVQQKEw5GU1VFIFNU",
    "QyBBdGxhczENMAsGA1UECxMEVVpJUzEUMBIGA1UEAxMLQ1NDQS1SdXNzaWExHzAd",
    "BgkqhkiG9w0BCQEWEGNhbWFpbEBzdGNuZXQucnUwHhcNMjIwMjI4MTA0MjQ2WhcN",
    "MzQwMjI1MTA0MjQ2WjCBgDELMAkGA1UEBhMCUlUxDzANBgNVBAcMBk1vc2NvdzES",
    "MBAGA1UECgwJU1RDLUF0bGFzMQ0wCwYDVQQLDARVWklTMRwwGgYDVQQDDBNEb2N1",
    "bWVudF9TaWduZXJfMy41MR8wHQYJKoZIhvcNAQkBFhBjYW1haWxAc3RjbmV0LnJ1",
    "MIIBSzCCAQMGByqGSM49AgEwgfcCAQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAA",
    "AAAAAAAAAAAA////////////////MFsEIP////8AAAABAAAAAAAAAAAAAAAA////",
    "///////////8BCBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwMVBMSd",
    "NgiG5wSTamZ44ROdJreBn36QBEEEaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5",
    "RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9QIhAP////8AAAAA",
    "//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABNC/fO9tdWswlybyrKN5DWjq",
    "RAU9SDs4v8QAnFHysSgJa/THOmGfV4Xc1IIlU0PPVaacEmqh2Uonpl6UEI4QRVaj",
    "UjBQMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUh6hBQVQwYivY2H4KMSWkeXBD",
    "XakwHwYDVR0jBBgwFoAUhQxT9xYOXe9kpWd898GEkgXSspwwCQYHKoZIzj0EAQNH",
    "ADBEAiBtcZkULayUOn20W/FDY/XSa6gW4RCLLkbPDge7QZ3+mQIgMUxl931Jf6QP",
    "O7f6y6mZ+dfR9n9rrjl57E2GC6Co3P8=",
    "-----END CERTIFICATE-----",
  ].join("\n");

  it("decode certificate with special EC parameters", () => {
    // Reference: https://github.com/PeculiarVentures/x509/issues/88
    const cert = new X509Certificate(certWithSpecialEcParam);
    expect(cert.publicKey.algorithm.name).toBe("1.2.840.10045.2.1");
  });
});

describe("crypto", () => {
  const crypto = x509.cryptoProvider.get();

  describe("x509", () => {
    const pem =
      "MIIDljCCAn6gAwIBAgIOSETcxtRwD/qzf0FjVvEwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExGjAYBgNVBAsTEUZvciBEZW1vIFVzZSBPbmx5MSAwHgYDVQQDExdHbG9iYWxTaWduIERlbW8gUm9vdCBDQTAeFw0xNjA3MjAwMDAwMDBaFw0zNjA3MjAwMDAwMDBaMGYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRowGAYDVQQLExFGb3IgRGVtbyBVc2UgT25seTEgMB4GA1UEAxMXR2xvYmFsU2lnbiBEZW1vIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1i9RNgrJ4YAATN0J4KVGZjFGQVGFdcbKvfxrt0Bfusq2g81iVrZZjqTJnPSx4g6TdVcsEXU9GWlkFXKEtZzYM4ycbwLAeJQxQDEqkV03GV8ks2Jq/6jIm2DbByPiS5fvRQFQJLYuQHqXpjpOpmPiostUsg9ydMEqcacYV22a6A6Nrb1c1B6OL+X0u9bo30K+YYSw2Ngp3Tuuj9PDk6JS/0CPLcLo8JIFFc8t78lPDquNAOqTDwY/HTw4751iqLVem9q3EDKEeUS+x4gqsCD2pENA7PlQBza55BGOi/A+UAsmfee1oq2Glo9buXBgX+oJ3HnyelzJU9Ej4+yfH7rcvAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTqD8ID9OxgG83HZJVtOQMmftrrLzANBgkqhkiG9w0BAQsFAAOCAQEAAECKKpL0A2I+hsY881tIz7WqkLDuLh/ISzRVdsALYAxLhVDUHPckh5XyVRkpbTmirn+b5MpuwAI2R8A7Ld6aWWiibc7zGEZNvEKsUEYoJoYR0fuQs2cF7egiYjhFwFMX75w+kuI0Yelm3/3+BiJVtAXqmnQ4yRpGXqNJ4mQC8yWgQbZCLUpH/nqeQANeoaDr5Yg8IOuHRQzG6YNt/Cl9CetDd8WPrAkGm3T2iG0dXQ48VgkkXcNDtY+55nYjIO+N7i+WTh1fe3ArGxHBR3E44+WoA8ntfI1g65+GR0s6G8M7oS+kAFXIwugUGYEnTWp0m5bAn5NlD314IEOg4mnS8Q==";

    it("unsupported algorithm usage", () => {
      const pem = `-----BEGIN CERTIFICATE-----
MIICpzCCAhACAg4AMA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG
A1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE
MRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl
YiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw
ODIyMDcyNjQzWhcNMTcwODIxMDcyNjQzWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs
ZS5jb20wgfAwgagGByqGSM44BAEwgZwCQQDKVt7ZYtFRCzrm2/NTjl45YtMgVctQ
pLadAowFRydY13uhGw+JXyM+qmngfQkXImQpoYdIe+A8DWG2vaO3wKQ3AhUAxx6d
eaDs+XNHcbsiVQ1osvxrG8sCQHQYZDlSy/A5AFXrWXUNlTJbNhWDnitiG/95qYCe
FGnwYPp/WyhX+/lbDmQujkrbd4wYStudZM0cc4iDAWeOHQ0DQwACQDtK/S6POMQE
8aI+skBdNQn+Ch76kNDhztC/suOr9FbCSxnZ/CfhSgE1phOJyEkdR2jgErl3uh51
lo+7to76LLUwDQYJKoZIhvcNAQEFBQADgYEAnrmxZ3HB0LmVoFYdBJWxNBkRaFyn
jBmRsSJp2xvFg2nyAF77AOqBuFOFqOxg04eDxH8TGLQOWjqdyCFCY79AQlmkdB+8
Z5SWqPEwLJHVLd91O9avQwwRQT5TAxGXFkHTlQxOoaGfTsVQFqSDnlYC4mFjspA7
W+K8+llxOFmtVzU=
-----END CERTIFICATE-----`;
      const cert = new x509.X509Certificate(pem);
      expect(cert.publicKey.algorithm.name).toBe("1.2.840.10040.4.1");
      expect((cert.publicKey.algorithm as x509.UnknownAlgorithm).parameters?.byteLength).toBe(159);
    });

    it("read", () => {
      const cert = new x509.X509Certificate(Convert.FromBase64(pem));
      expect(cert.serialNumber).toBe("4844dcc6d4700ffab37f416356f1");
      expect(cert.subject).toBe("C=BE, O=GlobalSign nv-sa, OU=For Demo Use Only, CN=GlobalSign Demo Root CA");
      expect(cert.issuer).toBe("C=BE, O=GlobalSign nv-sa, OU=For Demo Use Only, CN=GlobalSign Demo Root CA");
      expect(cert.extensions.length).toBe(3);
    });

    it("verify", async () => {
      const cert = new x509.X509Certificate(Convert.FromBase64(pem));
      const ok = await cert.verify({ date: new Date(2020, 5, 7) });
      expect(ok).toBe(true);
    });

    describe("thumbprint", () => {
      it("default", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const thumbprint = await cert.getThumbprint();
        expect(Convert.ToHex(thumbprint)).toBe("0cfbca8d79cdc989e4dd64abbc2f979cc9e0ccb4");
      });

      it("SHA-256", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const thumbprint = await cert.getThumbprint("SHA-256");
        expect(Convert.ToHex(thumbprint)).toBe("3578985ded3c684a00d138596cadc96a37eb2dd01511b4b7b7135a55362153df");
      });

      it("SHA-256, custom crypto", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const thumbprint = await cert.getThumbprint("SHA-256", crypto);
        expect(Convert.ToHex(thumbprint)).toBe("3578985ded3c684a00d138596cadc96a37eb2dd01511b4b7b7135a55362153df");
      });

      it("default algorithm, custom crypto", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const thumbprint = await cert.getThumbprint(crypto);
        expect(Convert.ToHex(thumbprint)).toBe("0cfbca8d79cdc989e4dd64abbc2f979cc9e0ccb4");
      });
    });

    describe("getExtensions", () => {
      it("existing", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const extensions = cert.getExtensions("2.5.29.15");
        expect(extensions.length).toBe(1);
        expect(extensions[0] instanceof x509.KeyUsagesExtension).toBe(true);
      });

      it("class", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const extensions = cert.getExtensions(x509.KeyUsagesExtension);
        expect(extensions.length).toBe(1);
        expect(extensions[0] instanceof x509.KeyUsagesExtension).toBe(true);
      });

      it("null", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const extensions = cert.getExtensions("2.5.29.16");
        expect(extensions.length).toBe(0);
      });
    });

    describe("getExtension", () => {
      it("class", async () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const extension = cert.getExtension(x509.KeyUsagesExtension);
        expect(extension).toBeTruthy();
        expect(extension instanceof x509.KeyUsagesExtension).toBe(true);
      });
    });

    describe("toString", () => {
      it("hex", () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const hex = cert.toString("hex");
        expect(hex).toBe(
          "308203963082027ea003020102020e4844dcc6d4700ffab37f416356f1300d06092a864886f70d01010b05003066310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361311a3018060355040b1311466f722044656d6f20557365204f6e6c793120301e06035504031317476c6f62616c5369676e2044656d6f20526f6f74204341301e170d3136303732303030303030305a170d3336303732303030303030305a3066310b300906035504061302424531193017060355040a1310476c6f62616c5369676e206e762d7361311a3018060355040b1311466f722044656d6f20557365204f6e6c793120301e06035504031317476c6f62616c5369676e2044656d6f20526f6f7420434130820122300d06092a864886f70d01010105000382010f003082010a0282010100b58bd44d82b2786000133742782951998c519054615d71b2af7f1aedd017eeb2ada0f35895ad9663a932673d2c7883a4dd55cb045d4f465a59055ca12d67360ce3271bc0b01e250c500c4aa4574dc657c92cd89abfea3226d836c1c8f892e5fbd14054092d8b901ea5e98e93a998f8a8b2d52c83dc9d304a9c69c615db66ba03a36b6f573507a38bf97d2ef5ba37d0af98612c36360a774eeba3f4f0e4e894bfd023cb70ba3c24814573cb7bf253c3aae3403aa4c3c18fc74f0e3be758aa2d57a6f6adc40ca11e512fb1e20aac083da910d03b3e5401cdae790463a2fc0f9402c99f79ed68ab61a5a3d6ee5c1817fa82771e7c9e973254f448f8fb27c7eeb72f0203010001a3423040300e0603551d0f0101ff040403020106300f0603551d130101ff040530030101ff301d0603551d0e04160414ea0fc203f4ec601bcdc764956d3903267edaeb2f300d06092a864886f70d01010b0500038201010000408a2a92f403623e86c63cf35b48cfb5aa90b0ee2e1fc84b345576c00b600c4b8550d41cf7248795f25519296d39a2ae7f9be4ca6ec0023647c03b2dde9a5968a26dcef318464dbc42ac504628268611d1fb90b36705ede822623845c05317ef9c3e92e23461e966dffdfe062255b405ea9a7438c91a465ea349e26402f325a041b6422d4a47fe7a9e40035ea1a0ebe5883c20eb87450cc6e9836dfc297d09eb4377c58fac09069b74f6886d1d5d0e3c5609245dc343b58fb9e6762320ef8dee2f964e1d5f7b702b1b11c1477138e3e5a803c9ed7c8d60eb9f86474b3a1bc33ba12fa40055c8c2e8141981274d6a749b96c09f93650f7d782043a0e269d2f1",
        );
        const cert2 = new x509.X509Certificate(hex);
        expect(cert2.equal(cert)).toBe(true);
      });
      it("pem", () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const pem2 = cert.toString("pem");
        expect(pem2).toBe(`-----BEGIN CERTIFICATE-----
MIIDljCCAn6gAwIBAgIOSETcxtRwD/qzf0FjVvEwDQYJKoZIhvcNAQELBQAwZjEL
MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExGjAYBgNVBAsT
EUZvciBEZW1vIFVzZSBPbmx5MSAwHgYDVQQDExdHbG9iYWxTaWduIERlbW8gUm9v
dCBDQTAeFw0xNjA3MjAwMDAwMDBaFw0zNjA3MjAwMDAwMDBaMGYxCzAJBgNVBAYT
AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRowGAYDVQQLExFGb3IgRGVt
byBVc2UgT25seTEgMB4GA1UEAxMXR2xvYmFsU2lnbiBEZW1vIFJvb3QgQ0EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1i9RNgrJ4YAATN0J4KVGZjFGQ
VGFdcbKvfxrt0Bfusq2g81iVrZZjqTJnPSx4g6TdVcsEXU9GWlkFXKEtZzYM4ycb
wLAeJQxQDEqkV03GV8ks2Jq/6jIm2DbByPiS5fvRQFQJLYuQHqXpjpOpmPiostUs
g9ydMEqcacYV22a6A6Nrb1c1B6OL+X0u9bo30K+YYSw2Ngp3Tuuj9PDk6JS/0CPL
cLo8JIFFc8t78lPDquNAOqTDwY/HTw4751iqLVem9q3EDKEeUS+x4gqsCD2pENA7
PlQBza55BGOi/A+UAsmfee1oq2Glo9buXBgX+oJ3HnyelzJU9Ej4+yfH7rcvAgMB
AAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBTqD8ID9OxgG83HZJVtOQMmftrrLzANBgkqhkiG9w0BAQsFAAOCAQEAAECKKpL0
A2I+hsY881tIz7WqkLDuLh/ISzRVdsALYAxLhVDUHPckh5XyVRkpbTmirn+b5Mpu
wAI2R8A7Ld6aWWiibc7zGEZNvEKsUEYoJoYR0fuQs2cF7egiYjhFwFMX75w+kuI0
Yelm3/3+BiJVtAXqmnQ4yRpGXqNJ4mQC8yWgQbZCLUpH/nqeQANeoaDr5Yg8IOuH
RQzG6YNt/Cl9CetDd8WPrAkGm3T2iG0dXQ48VgkkXcNDtY+55nYjIO+N7i+WTh1f
e3ArGxHBR3E44+WoA8ntfI1g65+GR0s6G8M7oS+kAFXIwugUGYEnTWp0m5bAn5Nl
D314IEOg4mnS8Q==
-----END CERTIFICATE-----`);
        const cert2 = new x509.X509Certificate(pem2);
        expect(cert2.equal(cert)).toBe(true);
      });
      it("base64", () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const base64 = cert.toString("base64");
        expect(base64).toBe(
          "MIIDljCCAn6gAwIBAgIOSETcxtRwD/qzf0FjVvEwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExGjAYBgNVBAsTEUZvciBEZW1vIFVzZSBPbmx5MSAwHgYDVQQDExdHbG9iYWxTaWduIERlbW8gUm9vdCBDQTAeFw0xNjA3MjAwMDAwMDBaFw0zNjA3MjAwMDAwMDBaMGYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRowGAYDVQQLExFGb3IgRGVtbyBVc2UgT25seTEgMB4GA1UEAxMXR2xvYmFsU2lnbiBEZW1vIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1i9RNgrJ4YAATN0J4KVGZjFGQVGFdcbKvfxrt0Bfusq2g81iVrZZjqTJnPSx4g6TdVcsEXU9GWlkFXKEtZzYM4ycbwLAeJQxQDEqkV03GV8ks2Jq/6jIm2DbByPiS5fvRQFQJLYuQHqXpjpOpmPiostUsg9ydMEqcacYV22a6A6Nrb1c1B6OL+X0u9bo30K+YYSw2Ngp3Tuuj9PDk6JS/0CPLcLo8JIFFc8t78lPDquNAOqTDwY/HTw4751iqLVem9q3EDKEeUS+x4gqsCD2pENA7PlQBza55BGOi/A+UAsmfee1oq2Glo9buXBgX+oJ3HnyelzJU9Ej4+yfH7rcvAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTqD8ID9OxgG83HZJVtOQMmftrrLzANBgkqhkiG9w0BAQsFAAOCAQEAAECKKpL0A2I+hsY881tIz7WqkLDuLh/ISzRVdsALYAxLhVDUHPckh5XyVRkpbTmirn+b5MpuwAI2R8A7Ld6aWWiibc7zGEZNvEKsUEYoJoYR0fuQs2cF7egiYjhFwFMX75w+kuI0Yelm3/3+BiJVtAXqmnQ4yRpGXqNJ4mQC8yWgQbZCLUpH/nqeQANeoaDr5Yg8IOuHRQzG6YNt/Cl9CetDd8WPrAkGm3T2iG0dXQ48VgkkXcNDtY+55nYjIO+N7i+WTh1fe3ArGxHBR3E44+WoA8ntfI1g65+GR0s6G8M7oS+kAFXIwugUGYEnTWp0m5bAn5NlD314IEOg4mnS8Q==",
        );
        const cert2 = new x509.X509Certificate(base64);
        expect(cert2.equal(cert)).toBe(true);
      });
      it("base64url", () => {
        const cert = new x509.X509Certificate(Convert.FromBase64(pem));
        const base64url = cert.toString("base64url");
        expect(base64url).toBe(
          "MIIDljCCAn6gAwIBAgIOSETcxtRwD_qzf0FjVvEwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExGjAYBgNVBAsTEUZvciBEZW1vIFVzZSBPbmx5MSAwHgYDVQQDExdHbG9iYWxTaWduIERlbW8gUm9vdCBDQTAeFw0xNjA3MjAwMDAwMDBaFw0zNjA3MjAwMDAwMDBaMGYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRowGAYDVQQLExFGb3IgRGVtbyBVc2UgT25seTEgMB4GA1UEAxMXR2xvYmFsU2lnbiBEZW1vIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1i9RNgrJ4YAATN0J4KVGZjFGQVGFdcbKvfxrt0Bfusq2g81iVrZZjqTJnPSx4g6TdVcsEXU9GWlkFXKEtZzYM4ycbwLAeJQxQDEqkV03GV8ks2Jq_6jIm2DbByPiS5fvRQFQJLYuQHqXpjpOpmPiostUsg9ydMEqcacYV22a6A6Nrb1c1B6OL-X0u9bo30K-YYSw2Ngp3Tuuj9PDk6JS_0CPLcLo8JIFFc8t78lPDquNAOqTDwY_HTw4751iqLVem9q3EDKEeUS-x4gqsCD2pENA7PlQBza55BGOi_A-UAsmfee1oq2Glo9buXBgX-oJ3HnyelzJU9Ej4-yfH7rcvAgMBAAGjQjBAMA4GA1UdDwEB_wQEAwIBBjAPBgNVHRMBAf8EBTADAQH_MB0GA1UdDgQWBBTqD8ID9OxgG83HZJVtOQMmftrrLzANBgkqhkiG9w0BAQsFAAOCAQEAAECKKpL0A2I-hsY881tIz7WqkLDuLh_ISzRVdsALYAxLhVDUHPckh5XyVRkpbTmirn-b5MpuwAI2R8A7Ld6aWWiibc7zGEZNvEKsUEYoJoYR0fuQs2cF7egiYjhFwFMX75w-kuI0Yelm3_3-BiJVtAXqmnQ4yRpGXqNJ4mQC8yWgQbZCLUpH_nqeQANeoaDr5Yg8IOuHRQzG6YNt_Cl9CetDd8WPrAkGm3T2iG0dXQ48VgkkXcNDtY-55nYjIO-N7i-WTh1fe3ArGxHBR3E44-WoA8ntfI1g65-GR0s6G8M7oS-kAFXIwugUGYEnTWp0m5bAn5NlD314IEOg4mnS8Q",
        );
        const cert2 = new x509.X509Certificate(base64url);
        expect(cert2.equal(cert)).toBe(true);
      });
    });
  });

  it("Parse EdDSA certificate and validate it", async () => {
    const pem = `-----BEGIN CERTIFICATE-----
MIIBfzCCATGgAwIBAgIUfI5kSdcO2S0+LkpdL3b2VUJG10YwBQYDK2VwMDUxCzAJ
BgNVBAYTAklUMQ8wDQYDVQQHDAZNaWxhbm8xFTATBgNVBAMMDFRlc3QgZWQyNTUx
OTAeFw0yMDA5MDIxMzI1MjZaFw0zMDA5MDIxMzI1MjZaMDUxCzAJBgNVBAYTAklU
MQ8wDQYDVQQHDAZNaWxhbm8xFTATBgNVBAMMDFRlc3QgZWQyNTUxOTAqMAUGAytl
cAMhADupL/3LF2beQKKS95PeMPgKI6gxIV3QB9hjJC7/aCGFo1MwUTAdBgNVHQ4E
FgQUa6W9z536I1l4EmQXrh5y2JqASugwHwYDVR0jBBgwFoAUa6W9z536I1l4EmQX
rh5y2JqASugwDwYDVR0TAQH/BAUwAwEB/zAFBgMrZXADQQBvc3e+KJZaMzbX5TT9
kPP9QH8fAvkAV/IWDxZrBL9lhLaY0tDSv0zWbw624uidBKPgmVD5wm3ec60dNVeF
ZYYG
-----END CERTIFICATE-----`;

    const cert = new x509.X509Certificate(pem);
    const ok = await cert.verify({ signatureOnly: true });
    expect(cert.signatureAlgorithm).toEqual({ name: "Ed25519" });
    expect(ok).toBe(true);
  });
});
