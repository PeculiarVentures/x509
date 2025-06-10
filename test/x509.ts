import { describe, it, expect } from "vitest";
import { X509Certificate } from "../src";

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
