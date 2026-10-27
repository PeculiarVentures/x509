import { describe, it, expect, beforeAll } from "vitest";
import { base64, binary, toArrayBuffer } from "@peculiar/utils";
import * as x509 from "./index";

describe("crypto", () => {
  describe("PemData", () => {
    describe("from string buffer", () => {
      let hexRaw: ArrayBuffer;
      let pem: ArrayBuffer;
      let base64Raw: ArrayBuffer;
      let base64urlRaw: ArrayBuffer;

      beforeAll(() => {
        const pemString =
          "MIICdDCCAVwCAQAwLzEtMA8GA1UEAxMIdGVzdE5hbWUwGgYJKoZIhvcNAQkBEw10ZXN0QG1haWwubm90MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArut7tLrb1BEHXImMTWipet+3/J2isn7mBv278oP7YyOkmX/Vzxvk9nvSc/B1wh6kSo6nfaxYacNNSP3r+WQYaTeLm5TsDbUfCJYtvvTuYH0GVTM8Qm7QhMZKnyUy/D60WNcRM4pnBDSEMpKppi7HhfL37DZpQnsQfr9r8LQPWZ9t/mf+FsSeWyQOQcz+ob6cODfNQIvbzpaXXdNpKIHLPW+/e4af5/WlZ9wL5Sy7kOf4X6nErdl74s1vSji9goANSQkd5TbswtFPRNybikrrisz0HtsIq2uTGDY6t3iOEHTe5qe/ux4anjbSqKVuIQEQWQOKb4h+mHTc+EC5yknihQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAE7TU20ui1MLtxLM0UZMytYAjC7vtXxB5Vl6bzHUzZkVFW6oTeizqDxjeBtZ1SqErpgdyvzMvFSxF6f+679kl1/Zs2V0IPa4y58he3wTT/M1xCBN/bITY2cA4ETozbtK4cGoi6jY/0j8NcxTLfiBgwhE3ap+9GzLtWEhHWCXmpsohbvAktXSh1tLh4xmgoQoePEBSPbnaOmsonyzscKiBMASDvjrFdNbtD0uY2v/wYXwtRGvV/Q/O3lLWEosE4NdnZmgId4bm7ru48WucSnxuEJAkKUjDLrN0uqY/tKfX4Zy9w8Y/o+hk3QzNBVa3ZUvzDhVAmamQflvw3lXMm/JG4U=";
        const csr = new x509.Pkcs10CertificateRequest(toArrayBuffer(base64.decode(pemString)));
        pem = toArrayBuffer(binary.decode(csr.toString("pem")));
        hexRaw = toArrayBuffer(binary.decode(csr.toString("hex")));
        base64Raw = toArrayBuffer(binary.decode(csr.toString("base64")));
        base64urlRaw = toArrayBuffer(binary.decode(csr.toString("base64url")));
      });

      it("pem", () => {
        const csr = new x509.Pkcs10CertificateRequest(pem);
        expect(csr).toBeTruthy();
      });

      it("hex", () => {
        const csr = new x509.Pkcs10CertificateRequest(hexRaw);
        expect(csr).toBeTruthy();
      });

      it("base64", () => {
        const csr = new x509.Pkcs10CertificateRequest(base64Raw);
        expect(csr).toBeTruthy();
      });

      it("base64url", () => {
        const csr = new x509.Pkcs10CertificateRequest(base64urlRaw);
        expect(csr).toBeTruthy();
      });
    });
  });
});

describe("PemData.toArrayBuffer", () => {
  const der = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]);

  it.each([
    ["hex", "3003020101"],
    ["hex with whitespace", "30 03\n02\t01\r01"],
    ["base64", "MAMCAQE="],
    // v2 rejected Base64 text with whitespace here
    ["base64 with whitespace", "MAMC\nAQE="],
    ["base64url", "MAMCAQE"],
  ])("reads %s", (_name, text) => {
    expect(new Uint8Array(x509.PemData.toArrayBuffer(text))).toEqual(der);
  });

  it("pads odd-length hex with a leading zero", () => {
    expect(new Uint8Array(x509.PemData.toArrayBuffer("003020101"))).toEqual(new Uint8Array([0x00, 0x03, 0x02, 0x01, 0x01]));
  });

  it("returns an ArrayBuffer input as is", () => {
    const buffer = der.slice().buffer;
    expect(x509.PemData.toArrayBuffer(buffer)).toBe(buffer);
  });

  it("copies the bytes of a view", () => {
    const view = der.slice();
    const raw = x509.PemData.toArrayBuffer(view);
    expect(raw).not.toBe(view.buffer);
    view[4] = 0x02;
    expect(new Uint8Array(raw)).toEqual(der);
  });

  it("rejects text in no supported encoding", () => {
    expect(() => x509.PemData.toArrayBuffer("@@@@")).toThrow(TypeError);
  });
});
