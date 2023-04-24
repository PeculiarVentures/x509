import * as assert from "assert";
import * as x509 from "../src";

context("validation_rules", () => {
  const certsTree = new x509.X509Certificates();
  const certsTreeCyclic = new x509.X509Certificates();

  const pems = [
    `-----BEGIN CERTIFICATE-----
MIIBlDCCATmgAwIBAgIUf2jj+cgKVMw5pD1GMocG1YpExEwwCgYIKoZIzj0EAwIw
JjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0MQ0wCwYDVQQKEwRUZXN0MB4XDTIyMTIy
NjA2NDIwNloXDTQyMTIyNjA2NDIwNlowJjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0
MQ0wCwYDVQQKEwRUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEO60ORwIK
ZfZ0wxiqf97Mezc28fVFVnuyNCnTNVm2iztE03K3ZrLD0rZuohvJmNvB1DdgZSJS
NHIYp7U8LnKh36NFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8C
AQEwHQYDVR0OBBYEFLlAZeqsu58hI2DV8kaz4aLR2YHbMAoGCCqGSM49BAMCA0kA
MEYCIQDNC+Qqd5qL0VFzc4Cpk5flsxWtADnKr+bO/QeX7f0VPwIhANUETaqaXkpj
Cuv/UlaFeXwPEDtbvhgY8FIBW8CNRLyA
-----END CERTIFICATE-----`,
    `-----BEGIN CERTIFICATE-----
MIICajCCAhGgAwIBAgIUfw1rwZ/YgkthPxrsy0Tq/epRLmMwCgYIKoZIzj0EAwIw
JjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0MQ0wCwYDVQQKEwRUZXN0MB4XDTIyMTIy
NjA2NDIwNloXDTMyMTIyNjA2NDIwNlowLjEdMBsGA1UEAxMUSW50ZXJtZWRpYXRl
IENBIGNlcnQxDTALBgNVBAoTBFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATbkHNu+8Co/+TSG0Pufs/HEs5SELP39OCzKovPbUYSA8IHJF95Rh+wfPcOcLMk
b/r5Nb9WigwrJNosmdApaNbfo4IBEzCCAQ8wDgYDVR0PAQH/BAQDAgEGMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFPu3XMGqhbPRsLmHqguYSBura+VTMB8G
A1UdIwQYMBaAFLlAZeqsu58hI2DV8kaz4aLR2YHbMDQGA1UdJQQtMCsGCCsGAQUF
BwMCBggrBgEFBQcDBAYKKwYBBAGCNwoDDAYJYIZIAYb6aygLMD4GCCsGAQUFBwEB
BDIwMDAuBggrBgEFBQcwAoYiaHR0cHM6Ly9sb2NhbGhvc3Q6ODAwMC9yb290LWNh
LmNlcjAzBgNVHR8ELDAqMCigJqAkhiJodHRwczovL2xvY2FsaG9zdDo4MDAwL3Jv
b3QtY2EuY3JsMAoGCCqGSM49BAMCA0cAMEQCIF/+Ggzw4Pm7OvCrcekUA1/zMk9B
e0L6M67T90dD0E1bAiAOeDfLu0bFCF4YANfOOkOL3howf8ZGsSkes5lYiDsyuQ==
-----END CERTIFICATE-----`,
    `-----BEGIN CERTIFICATE-----
MIICajCCAhGgAwIBAgIUf1UGkdteyPJ3mXOh8Rwdnd1udo8wCgYIKoZIzj0EAwIw
JjEVMBMGA1UEAxMMUm9vdCBDQSBjZXJ0MQ0wCwYDVQQKEwRUZXN0MB4XDTIyMTIy
NjA2NDIwNloXDTMzMTIyNjA2NDIwNlowLjEdMBsGA1UEAxMUSW50ZXJtZWRpYXRl
IENBIGNlcnQxDTALBgNVBAoTBFRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATbkHNu+8Co/+TSG0Pufs/HEs5SELP39OCzKovPbUYSA8IHJF95Rh+wfPcOcLMk
b/r5Nb9WigwrJNosmdApaNbfo4IBEzCCAQ8wDgYDVR0PAQH/BAQDAgEGMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFPu3XMGqhbPRsLmHqguYSBura+VTMB8G
A1UdIwQYMBaAFLlAZeqsu58hI2DV8kaz4aLR2YHbMDQGA1UdJQQtMCsGCCsGAQUF
BwMCBggrBgEFBQcDBAYKKwYBBAGCNwoDDAYJYIZIAYb6aygLMD4GCCsGAQUFBwEB
BDIwMDAuBggrBgEFBQcwAoYiaHR0cHM6Ly9sb2NhbGhvc3Q6ODAwMC9yb290LWNh
LmNlcjAzBgNVHR8ELDAqMCigJqAkhiJodHRwczovL2xvY2FsaG9zdDo4MDAwL3Jv
b3QtY2EuY3JsMAoGCCqGSM49BAMCA0cAMEQCIEztc/6I/ZmnCc8SlG/cywtQ5kDV
Bazy1QpYznxEOYCdAiAQh3CocvGnNsZM/oPSRXeuhEaXZDa4N7/tm58OHvY97g==
-----END CERTIFICATE-----`,
    `-----BEGIN CERTIFICATE-----
MIICdTCCAhugAwIBAgIUfxnEkpHrr45lBnTg6xIrjGVf5eEwCgYIKoZIzj0EAwIw
LjEdMBsGA1UEAxMUSW50ZXJtZWRpYXRlIENBIGNlcnQxDTALBgNVBAoTBFRlc3Qw
HhcNMjIxMjI2MDY0MjA2WhcNMzAxMjI2MDY0MjA2WjAwMR8wHQYDVQQDExZJbnRl
cm1lZGlhdGUgQ0EgY2VydCAyMQ0wCwYDVQQKEwRUZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAELsrIM/ggFlFh8lPYTc++wmAYRgzu9uEnQ6fEYCMKW6xhm8eT
+6VOn778ige80ghDI7jGedwXQpupB9UoSHIcPaOCARMwggEPMA4GA1UdDwEB/wQE
AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTDQOJ+ILUOWkQeYjEX
rp5eaTPtWjAfBgNVHSMEGDAWgBT7t1zBqoWz0bC5h6oLmEgbq2vlUzA0BgNVHSUE
LTArBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcKAwwGCWCGSAGG+msoCzA+
BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAKGImh0dHBzOi8vbG9jYWxob3N0Ojgw
MDAvcm9vdC1jYS5jZXIwMwYDVR0fBCwwKjAooCagJIYiaHR0cHM6Ly9sb2NhbGhv
c3Q6ODAwMC9yb290LWNhLmNybDAKBggqhkjOPQQDAgNIADBFAiEA1shsEZVejICl
rMOygvtCNOnCtkBJi+mDPmpa2rjHNpoCIElnpb/gGOt5uHNJyX+i7abIagrg7GAv
/3hTFUKAAIBQ
-----END CERTIFICATE-----`,
    `-----BEGIN CERTIFICATE-----
MIICdDCCAhugAwIBAgIUf4R93WceOdqW3vbqBA/dAX0Nt+IwCgYIKoZIzj0EAwIw
LjEdMBsGA1UEAxMUSW50ZXJtZWRpYXRlIENBIGNlcnQxDTALBgNVBAoTBFRlc3Qw
HhcNMjIxMjI2MDY0MjA2WhcNMzAxMjI2MDY0MjA2WjAwMR8wHQYDVQQDExZJbnRl
cm1lZGlhdGUgQ0EgY2VydCAyMQ0wCwYDVQQKEwRUZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAELsrIM/ggFlFh8lPYTc++wmAYRgzu9uEnQ6fEYCMKW6xhm8eT
+6VOn778ige80ghDI7jGedwXQpupB9UoSHIcPaOCARMwggEPMA4GA1UdDwEB/wQE
AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTDQOJ+ILUOWkQeYjEX
rp5eaTPtWjAfBgNVHSMEGDAWgBT7t1zBqoWz0bC5h6oLmEgbq2vlUzA0BgNVHSUE
LTArBggrBgEFBQcDAgYIKwYBBQUHAwQGCisGAQQBgjcKAwwGCWCGSAGG+msoCzA+
BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAKGImh0dHBzOi8vbG9jYWxob3N0Ojgw
MDAvcm9vdC1jYS5jZXIwMwYDVR0fBCwwKjAooCagJIYiaHR0cHM6Ly9sb2NhbGhv
c3Q6ODAwMC9yb290LWNhLmNybDAKBggqhkjOPQQDAgNHADBEAiAE5GMn7gMYzT2k
IOkrKcMuhjWBd5A/MHGjgjIhxWgvxwIgMWvxpF+bFHNYNI3R6g9mEKmxOmOtlA85
NiXJIDi481Q=
-----END CERTIFICATE-----`,
    `-----BEGIN CERTIFICATE-----
MIICdzCCAh2gAwIBAgIUf6GxFUpBX6d5XbJx4tEdzrvVP2EwCgYIKoZIzj0EAwIw
MDEfMB0GA1UEAxMWSW50ZXJtZWRpYXRlIENBIGNlcnQgMjENMAsGA1UEChMEVGVz
dDAeFw0yMjEyMjYwNjQyMDZaFw0yOTEyMjYwNjQyMDZaMDAxHzAdBgNVBAMTFklu
dGVybWVkaWF0ZSBDQSBjZXJ0IDQxDTALBgNVBAoTBFRlc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASQxMPRZ47F0beWGaJ9Y/oGN2xpwnKnh/Qiv0sU9WAYY3Wo
JzKJUKUNisdwnPGumYzpzioRHWh/HXU6nD9mpRL7o4IBEzCCAQ8wDgYDVR0PAQH/
BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLsqv0Nk0Y7PevkG
zvuYNg6uB+wAMB8GA1UdIwQYMBaAFMNA4n4gtQ5aRB5iMReunl5pM+1aMDQGA1Ud
JQQtMCsGCCsGAQUFBwMCBggrBgEFBQcDBAYKKwYBBAGCNwoDDAYJYIZIAYb6aygL
MD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAoYiaHR0cHM6Ly9sb2NhbGhvc3Q6
ODAwMC9yb290LWNhLmNlcjAzBgNVHR8ELDAqMCigJqAkhiJodHRwczovL2xvY2Fs
aG9zdDo4MDAwL3Jvb3QtY2EuY3JsMAoGCCqGSM49BAMCA0gAMEUCIQDx7IF2M7Sk
bhfeCt1wkwGisDgSAqOZWLiI0+GTTlqvRgIgZIb7vebpC65vIbD6oBG+QphUdirr
CEn5YlJTjpTwKK0=
-----END CERTIFICATE-----`
  ];

  pems.forEach((pem) => certsTree.push(new x509.X509Certificate(pem)));

  const pemsCyclic = [
    `-----BEGIN CERTIFICATE-----
MIIBDzCBtqADAgECAgEBMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMTBUNBICMxMB4X
DTE5MTIzMTIzMDAwMFoXDTIwMDEwMjIzMDAwMFowDzENMAsGA1UEAxMETGVhZjBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABFPEQoYL4atthlEb7fbGffIxaPyPNone
k9QicvPmLSMXhZlxbU60ibWlRkvIFm2pipBbtlBWGvHem2DjbgypCoyjAjAAMAoG
CCqGSM49BAMCA0gAMEUCIQCO3LxmEl/pSSCOY701C2NHEC0gJnbY2z+/1JOXIa46
XQIgKeQnjIrehjbcF5P4+jwZUc2TtQ+upr3Z7dVYFnkwImM=
-----END CERTIFICATE-----`,
    `-----BEGIN CERTIFICATE-----
MIIBEDCBt6ADAgECAgECMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMTBUNBICMyMB4X
DTE5MTIzMTIzMDAwMFoXDTIwMDEwMjIzMDAwMFowEDEOMAwGA1UEAxMFQ0EgIzEw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASqpVfqWmlOf1jLKQ4n/VyI/AiVQLXQ
Maz6e5KWtUesAGE0/4aKh4sUKNxVdxSGSP9oc2w2vuT2Q+KQVkD/BQbvowIwADAK
BggqhkjOPQQDAgNIADBFAiAmXSOeo4AzAVHoYbufJCZBL7m2piY4ZVLtotEpVWVv
BQIhAKdxCaAd/Cr9t0vAY8LNzh6wwc1cK5RFCqP0KNR49sxS
-----END CERTIFICATE-----`,
    `-----BEGIN CERTIFICATE-----
MIIBEDCBtqADAgECAgEDMAoGCCqGSM49BAMCMA8xDTALBgNVBAMTBExlYWYwHhcN
MTkxMjMxMjMwMDAwWhcNMjAwMTAyMjMwMDAwWjAQMQ4wDAYDVQQDEwVDQSAjMjBZ
MBMGByqGSM49AgEGCCqGSM49AwEHA0IABAI+Ld1lcjiWZ0phLbCsxdf49+6SGEpi
l592T7uUMPKBggyFm5s2iS0YYAUKKHO9/sEgfcSu7mzbMFhhSbWDZP2jAjAAMAoG
CCqGSM49BAMCA0kAMEYCIQDbuFsqHHtz70zWH0KMBNF4BOXT6PwCiv4PjkmNH0qh
ywIhAM3wLiQIf5nTUTW7lCozoBGwP3MSOx5ZeQgTK6z4qOBI
-----END CERTIFICATE-----`,
  ];

  pemsCyclic.forEach((pem) => certsTreeCyclic.push(new x509.X509Certificate(pem)));

  const tests: {
    name: string;
    args: {
      cert: x509.X509Certificate;
      certsTree: x509.X509Certificates;
      rule: () => x509.rules.ChainRule;
    },
    want: {
      status: boolean;
      chain: string; // идентификаторы сертификатов в цепочке написанные через запятую
    };
  }[] = [
      {
        name: "checkDate between notBefore and notAfter. All certificates are valid",
        args: {
          cert: certsTree[5],
          certsTree,
          rule: () => {
            const r = new x509.rules.ExpiredRule();
            r.checkDate = new Date("2023/08/19");

            return r;
          },
        },
        want: {
          status: true,
          chain: "7fa1b1154a415fa7795db271e2d11dcebbd53f61,7f19c49291ebaf8e650674e0eb122b8c655fe5e1,7f0d6bc19fd8824b613f1aeccb44eafdea512e63,7f68e3f9c80a54cc39a43d46328706d58a44c44c",
        },
      },
      {
        name: "checkDate is less than notBefore",
        args: {
          cert: certsTree[5],
          certsTree,
          rule: () => {
            const r = new x509.rules.ExpiredRule();
            r.checkDate = new Date("2020/08/18");

            return r;
          },
        },
        want: {
          status: false,
          chain: "7fa1b1154a415fa7795db271e2d11dcebbd53f61,7f847ddd671e39da96def6ea040fdd017d0db7e2,7f550691db5ec8f2779973a1f11c1d9ddd6e768f,7f68e3f9c80a54cc39a43d46328706d58a44c44c",
        },
      },
      {
        name: "checkDate is greater than notAfter",
        args: {
          cert: certsTree[5],
          certsTree,
          rule: () => {
            const r = new x509.rules.ExpiredRule();
            r.checkDate = new Date("2043/08/18");

            return r;
          },
        },
        want: {
          status: false,
          chain: "7fa1b1154a415fa7795db271e2d11dcebbd53f61,7f847ddd671e39da96def6ea040fdd017d0db7e2,7f550691db5ec8f2779973a1f11c1d9ddd6e768f,7f68e3f9c80a54cc39a43d46328706d58a44c44c",
        },
      },
      {
        name: "Rule for checking certificate chains for mixed states",
        args: {
          cert: certsTree[5],
          certsTree,
          rule: () => {
            const r = new x509.rules.ExpiredRule();
            r.checkDate = new Date("2031/12/26");

            return r;
          },
        },
        want: {
          status: false,
          chain: "7fa1b1154a415fa7795db271e2d11dcebbd53f61,7f847ddd671e39da96def6ea040fdd017d0db7e2,7f550691db5ec8f2779973a1f11c1d9ddd6e768f,7f68e3f9c80a54cc39a43d46328706d58a44c44c",
        },
      },
      {
        name: "No trusted certificates",
        args: {
          cert: certsTree[5],
          certsTree,
          rule: () => {
            const r = new x509.rules.TrustedRule();

            return r;
          },
        },
        want: {
          status: false,
          chain: "7fa1b1154a415fa7795db271e2d11dcebbd53f61,7f847ddd671e39da96def6ea040fdd017d0db7e2,7f550691db5ec8f2779973a1f11c1d9ddd6e768f,7f68e3f9c80a54cc39a43d46328706d58a44c44c",
        },
      },
      {
        name: "The chain of certificates is not cyclic",
        args: {
          cert: certsTree[5],
          certsTree,
          rule: () => {
            const r = new x509.rules.CyclicRule();

            return r;
          },
        },
        want: {
          status: true,
          chain: "7fa1b1154a415fa7795db271e2d11dcebbd53f61,7f19c49291ebaf8e650674e0eb122b8c655fe5e1,7f0d6bc19fd8824b613f1aeccb44eafdea512e63,7f68e3f9c80a54cc39a43d46328706d58a44c44c",
        },
      },
      {
        name: "The chain of certificates is cyclic",
        args: {
          cert: certsTreeCyclic[0],
          certsTree: certsTreeCyclic,
          rule: () => {
            const r = new x509.rules.CyclicRule();

            return r;
          },
        },
        want: {
          status: false,
          chain: "01,02,03,01",
        },
      },
    ];

  for (const t of tests) {
    it(t.name, async () => {
      const validator = new x509.X509ChainValidator();
      validator.rules.clear();
      validator.rules.add(t.args.rule());
      validator.certificateStorage.certificates = t.args.certsTree;
      const result = await validator.validate(t.args.cert);

      assert.strictEqual(result.status, t.want.status);
      assert.strictEqual(result.items.map((c) => c.certificate.serialNumber).join(","), t.want.chain);
    });
  }
});