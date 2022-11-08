import * as assert from "assert";
import { Convert } from "pvtsutils";
import * as src from "../src";

context("PEM", () => {

  const base64_splitted = "LLrHB0eJzyhP+/fSStdW8okeEnv47jxe7SJ/iN72ohNcUk2jHEUSoH1nvNSIWL9M\n8tEjmF/zxB+bATMtPjCUWbz8Lr9wloXIkjHUlBLpvXR0UrUzYbkNpk0agV2IzUpk\nJ6UiRRGcDSvzrsoK+oNvqu6z7Xs5Xfz5rDqUcMlK1Z6720dcBWGGsDLpTpSCnpot\ndXd/H5LMDWnonNvPCwQUHg==";
  const base64 = base64_splitted.replace(/\n/g, "");
  const rawData = Convert.FromBase64(base64);

  context("decodeWithHeaders", () => {

    interface PemTest {
      type: string;
      headers: src.PemHeader[];
      rawData: string;
    }

    function mapPemStruct(pem: src.PemStruct): PemTest {
      return { ...pem, rawData: Convert.ToBase64(pem.rawData) };
    }


    const tests: {
      name: string;
      pem: string;
      want: PemTest[] | Error;
    }[] = [
        {
          name: "simple pem",
          pem: [
            "-----BEGIN SOME-----",
            base64_splitted,
            "-----END SOME-----"
          ].join("\n"),
          want: [
            {
              type: "SOME",
              headers: [],
              rawData: base64,
            }
          ],
        },
        {
          name: "simple pem with CRLF",
          pem: [
            "-----BEGIN SOME-----",
            base64_splitted.replace(/\n/g, "\r\n"),
            "-----END SOME-----"
          ].join("\r\n"),
          want: [
            {
              type: "SOME",
              headers: [],
              rawData: base64,
            }
          ],
        },
        {
          name: "pem with blank line",
          pem: [
            "-----BEGIN SOME-----",
            "", // blank line
            base64_splitted,
            "-----END SOME-----"
          ].join("\n"),
          want: [
            {
              type: "SOME",
              headers: [],
              rawData: base64,
            }
          ],
        },
        {
          name: "pem with headers",
          pem: [
            "-----BEGIN PRIVACY-ENHANCED MESSAGE-----",
            "Proc-Type: 4,ENCRYPTED",
            "Content-Domain: RFC822",
            "DEK-Info: DES-CBC,F8143EDE5960C597",
            "Originator-ID-Symmetric: linn@zendia.enet.dec.com,,",
            "Recipient-ID-Symmetric: linn@zendia.enet.dec.com,ptf-kmc,3",
            "Key-Info: DES-ECB,RSA-MD2,9FD3AAD2F2691B9A,",
            "          B70665BB9BF7CBCDA60195DB94F727D3",
            "Recipient-ID-Symmetric: pem-dev@tis.com,ptf-kmc,4", // repeated headers
            "Key-Info: DES-ECB,RSA-MD2,161A3F75DC82EF26,",
            "          E2EF532C65CBCFF79F83A2658132DB47",
            "",
            base64_splitted,
            "-----END PRIVACY-ENHANCED MESSAGE-----",
          ].join("\n"),
          want: [
            {
              type: "PRIVACY-ENHANCED MESSAGE",
              headers: [
                { key: "Proc-Type", value: "4,ENCRYPTED" },
                { key: "Content-Domain", value: "RFC822" },
                { key: "DEK-Info", value: "DES-CBC,F8143EDE5960C597" },
                { key: "Originator-ID-Symmetric", value: "linn@zendia.enet.dec.com,," },
                { key: "Recipient-ID-Symmetric", value: "linn@zendia.enet.dec.com,ptf-kmc,3" },
                { key: "Key-Info", value: "DES-ECB,RSA-MD2,9FD3AAD2F2691B9A,B70665BB9BF7CBCDA60195DB94F727D3" },
                { key: "Recipient-ID-Symmetric", value: "pem-dev@tis.com,ptf-kmc,4" },
                { key: "Key-Info", value: "DES-ECB,RSA-MD2,161A3F75DC82EF26,E2EF532C65CBCFF79F83A2658132DB47" },
              ],
              rawData: base64,
            }
          ],
        },
        {
          name: "multiple PEM blocks",
          pem: [
            "odd text",
            "-----BEGIN SOME1-----",
            base64_splitted,
            "-----END SOME1-----",
            "",
            "-----BEGIN SOME2-----",
            "Key1: Value1",
            "",
            base64_splitted,
            "-----END SOME2-----",
            "odd text",
            "-----BEGIN SOME1-----",
            "",
            base64_splitted,
            "-----END SOME2-----", // incorrect type
          ].join("\n"),
          want: [
            {
              type: "SOME1",
              headers: [],
              rawData: base64,
            },
            {
              type: "SOME2",
              headers: [
                { key: "Key1", value: "Value1" },
              ],
              rawData: base64,
            },
          ]
        },
        {
          name: "BEGIN and END types are not equal",
          pem: [
            "-----BEGIN SOME1-----",
            base64_splitted,
            "-----END SOME2-----"
          ].join("\n"),
          want: [],
        },
        {
          name: "odd text before BEGIN",
          pem: [
            "Some: value",
            "-----BEGIN SOME-----",
            base64_splitted,
            "-----END SOME-----"
          ].join("\n"),
          want: [
            {
              type: "SOME",
              headers: [],
              rawData: base64,
            },
          ],
        },
      ];
    tests.forEach(t => {
      it(t.name, () => {
        if (t.want instanceof Error) {
          assert.throws(() => {
            src.PemConverter.decodeWithHeaders(t.pem);
          }, t.want);
        } else {
          const res = src.PemConverter.decodeWithHeaders(t.pem);

          assert.deepEqual(res.map(mapPemStruct), t.want);
        }
      });
    });

  });

  context("encode", () => {

    const tests: {
      name: string;
      args: { a: BufferSource | BufferSource[] | src.PemStructEncodeParams[], b?: string; };
      want: string | Error;
    }[] = [
        {
          name: "PEM without headers from PemStruct",
          args: {
            a: [
              {
                type: "SOME",
                rawData,
              }
            ]
          },
          want: [
            "-----BEGIN SOME-----",
            base64_splitted,
            "-----END SOME-----",
          ].join("\n"),
        },
        {
          name: "PEM with headers from PemStruct",
          args: {
            a: [
              {
                type: "SOME",
                headers: [
                  { key: "Key1", value: "Value1" },
                  { key: "Key2", value: "Value2" },
                  { key: "Key1", value: "Value3" }, // repeated key
                ],
                rawData,
              }
            ]
          },
          want: [
            "-----BEGIN SOME-----",
            "Key1: Value1",
            "Key2: Value2",
            "Key1: Value3",
            "",
            base64_splitted,
            "-----END SOME-----",
          ].join("\n"),
        },
        {
          name: "multiple PEM blocks",
          args: {
            a: [
              {
                type: "SOME1",
                rawData,
              },
              {
                type: "SOME2",
                headers: [
                  { key: "Key1", value: "Value1" },
                ],
                rawData,
              },
            ]
          },
          want: [
            "-----BEGIN SOME1-----",
            base64_splitted,
            "-----END SOME1-----",
            "-----BEGIN SOME2-----",
            "Key1: Value1",
            "",
            base64_splitted,
            "-----END SOME2-----",
          ].join("\n"),
        },
        {
          name: "PEM from BufferSource",
          args: {
            a: rawData,
            b: "SOME",
          },
          want: [
            "-----BEGIN SOME-----",
            base64_splitted,
            "-----END SOME-----",
          ].join("\n"),
        },
        {
          name: "PEM from BufferSource[]",
          args: {
            a: [rawData, rawData],
            b: "SOME",
          },
          want: [
            "-----BEGIN SOME-----",
            base64_splitted,
            "-----END SOME-----",
            "-----BEGIN SOME-----",
            base64_splitted,
            "-----END SOME-----",
          ].join("\n"),
        },
      ];

    tests.forEach(t => {
      it(t.name, () => {
        if (t.want instanceof Error) {
          assert.throws(() => {
            src.PemConverter.encode.call<unknown, any[], unknown>(src.PemConverter, t.args.a, t.args.b);
          }, t.want);
        } else {
          const pem = src.PemConverter.encode.call<unknown, any[], unknown>(src.PemConverter, t.args.a, t.args.b);
          assert.strictEqual(pem, t.want);
        }
      });
    });

  });

});
