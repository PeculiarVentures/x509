import { describe, it, expect, beforeAll } from "vitest";
import { Convert } from "pvtsutils";
import * as x509 from "./index";

describe("crypto", () => {
  describe("PemData", () => {
    describe("from string buffer", () => {
      let hex: ArrayBuffer;
      let pem: ArrayBuffer;
      let base64: ArrayBuffer;
      let base64url: ArrayBuffer;

      beforeAll(() => {
        const pemString =
          "MIICdDCCAVwCAQAwLzEtMA8GA1UEAxMIdGVzdE5hbWUwGgYJKoZIhvcNAQkBEw10ZXN0QG1haWwubm90MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArut7tLrb1BEHXImMTWipet+3/J2isn7mBv278oP7YyOkmX/Vzxvk9nvSc/B1wh6kSo6nfaxYacNNSP3r+WQYaTeLm5TsDbUfCJYtvvTuYH0GVTM8Qm7QhMZKnyUy/D60WNcRM4pnBDSEMpKppi7HhfL37DZpQnsQfr9r8LQPWZ9t/mf+FsSeWyQOQcz+ob6cODfNQIvbzpaXXdNpKIHLPW+/e4af5/WlZ9wL5Sy7kOf4X6nErdl74s1vSji9goANSQkd5TbswtFPRNybikrrisz0HtsIq2uTGDY6t3iOEHTe5qe/ux4anjbSqKVuIQEQWQOKb4h+mHTc+EC5yknihQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE7TU20ui1MLtxLM0UZMytYAjC7vtXxB5Vl6bzHUzZkVFW6oTeizqDxjeBtZ1SqErpgdyvzMvFSxF6f+679kl1/Zs2V0IPa4y58he3wTT/M1xCBN/bITY2cA4ETozbtK4cGoi6jY/0j8NcxTLfiBgwhE3ap+9GzLtWEhHWCXmpsohbvAktXSh1tLh4xmgoQoePEBSPbnaOmsonyzscKiBMASDvjrFdNbtD0uY2v/wYXwtRGvV/Q/O3lLWEosE4NdnZmgId4bm7ru48WucSnxuEJAkKUjDLrN0uqY/tKfX4Zy9w8Y/o+hk3QzNBVa3ZUvzDhVAmamQflvw3lXMm/JG4U=";
        const csr = new x509.Pkcs10CertificateRequest(Convert.FromBase64(pemString));
        pem = Convert.FromBinary(csr.toString("pem"));
        hex = Convert.FromBinary(csr.toString("hex"));
        base64 = Convert.FromBinary(csr.toString("base64"));
        base64url = Convert.FromBinary(csr.toString("base64url"));
      });

      it("pem", () => {
        const csr = new x509.Pkcs10CertificateRequest(pem);
        expect(csr).toBeTruthy();
      });

      it("hex", () => {
        const csr = new x509.Pkcs10CertificateRequest(hex);
        expect(csr).toBeTruthy();
      });

      it("base64", () => {
        const csr = new x509.Pkcs10CertificateRequest(base64);
        expect(csr).toBeTruthy();
      });

      it("base64url", () => {
        const csr = new x509.Pkcs10CertificateRequest(base64url);
        expect(csr).toBeTruthy();
      });
    });
  });
});
