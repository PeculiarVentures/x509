import * as assert from "assert";
import * as asn1X509 from "@peculiar/asn1-x509";
import * as x509 from "../src";
import * as asn1Schema from "@peculiar/asn1-schema";

context("GeneralName", () => {

  context("constructor", () => {

    const tests: {
      name: string;
      args: x509.JsonGeneralName | asn1X509.GeneralName | BufferSource;
      want?: x509.JsonGeneralName;
      wantError?: Error;
    }[] = [
        {
          name: "dn:CN=name, O=org",
          args: { type: "dn", value: "CN=name,O=org" },
          want: { type: "dn", value: "CN=name, O=org" },
        },
        {
          name: "dns:some.com",
          args: { type: "dns", value: "some.com" },
          want: { type: "dns", value: "some.com" },
        },
        {
          name: "email:some@email.com",
          args: { type: "email", value: "some@email.com" },
          want: { type: "email", value: "some@email.com" },
        },
        {
          name: "guid:33636766-dee4-4ac5-a4ae-af8380c7a655",
          args: { type: "guid", value: "33636766-DEE4-4AC5-A4AE-AF8380C7A655" },
          want: { type: "guid", value: "33636766-dee4-4ac5-a4ae-af8380c7a655" },
        },
        {
          name: "guid:incorrect",
          args: { type: "guid", value: "incorrect" },
          wantError: new Error("Cannot parse GUID value. Value doesn't match to regular expression"),
        },
        {
          name: "id:1.2.3.4.5.6",
          args: { type: "id", value: "1.2.3.4.5.6" },
          want: { type: "id", value: "1.2.3.4.5.6" },
        },
        {
          name: "ip:192.168.0.1",
          args: { type: "ip", value: "192.168.0.1" },
          want: { type: "ip", value: "192.168.0.1" },
        },
        {
          name: "upn:user@domain.com",
          args: { type: "upn", value: "user@domain.com" },
          want: { type: "upn", value: "user@domain.com" },
        },
        {
          name: "url:https://some.com",
          args: { type: "url", value: "https://some.com" },
          want: { type: "url", value: "https://some.com" },
        },
        {
          name: "raw:BufferSource",
          args: Buffer.from("8208736f6d652e636f6d", "hex"),
          want: { type: "dns", value: "some.com" },
        },
        {
          name: "asn:GeneralName",
          args: asn1Schema.AsnConvert.parse(Buffer.from("8208736f6d652e636f6d", "hex"), asn1X509.GeneralName),
          want: { type: "dns", value: "some.com" },
        },
      ];

    for (const t of tests) {
      it(t.name, () => {
        function create(): x509.GeneralName {
          if ("type" in t.args) {
            return new x509.GeneralName(t.args.type, t.args.value);
          }

          return new x509.GeneralName(t.args as BufferSource);
        }

        if (t.wantError) {

          assert.throws(create, t.wantError);
        } else {
          const obj = create().toJSON();
          assert.deepStrictEqual(obj, t.want);
        }
      });
    }

  });

  context("toString", () => {
    const tests: {
      name: string;
      args: { type: x509.GeneralNameType; value: string; };
      want: string;
    }[] = [
        {
          name: "dn:CN=name, O=org",
          args: { type: "dn", value: "CN=name,O=org" },
          want: "DN: CN=name, O=org",
        },
        {
          name: "dns:some.com",
          args: { type: "dns", value: "some.com" },
          want: "DNS: some.com",
        },
        {
          name: "email:some@email.com",
          args: { type: "email", value: "some@email.com" },
          want: "Email: some@email.com",
        },
        {
          name: "guid:33636766-dee4-4ac5-a4ae-af8380c7a655",
          args: { type: "guid", value: "33636766-DEE4-4AC5-A4AE-AF8380C7A655" },
          want: "GUID: 33636766-dee4-4ac5-a4ae-af8380c7a655",
        },
        {
          name: "id:1.2.3.4.5.6",
          args: { type: "id", value: "1.2.3.4.5.6" },
          want: "ID: 1.2.3.4.5.6",
        },
        {
          name: "ip:192.168.0.1",
          args: { type: "ip", value: "192.168.0.1" },
          want: "IP: 192.168.0.1",
        },
        {
          name: "upn:user@domain.com",
          args: { type: "upn", value: "user@domain.com" },
          want: "UPN: user@domain.com",
        },
        {
          name: "url:https://some.com",
          args: { type: "url", value: "https://some.com" },
          want: "URL: https://some.com",
        },
      ];
    for (const t of tests) {
      it(t.name, () => {
        const name = new x509.GeneralName(t.args.type, t.args.value);
        const text = name.toString("text");
        assert.strictEqual(text, t.want);
      });
    }
  });

});

context("GeneralNames", () => {

  context("constructor", () => {
    const raw = Buffer.from("302ba41f301d310d300b060355040313046e616d65310c300a060355040a13036f72678208736f6d652e636f6d", "hex");

    const tests: {
      name: string;
      args: x509.JsonGeneralNames
      | asn1X509.GeneralNames | asn1X509.GeneralName[]
      | BufferSource;
      want?: x509.JsonGeneralNames;
    }[] = [
        {
          name: "JSON",
          args: [
            { type: "dn", value: "CN=name, O=org" },
            { type: "dns", value: "some.com" }
          ],
          want: [
            { type: "dn", value: "CN=name, O=org" },
            { type: "dns", value: "some.com" }
          ],
        },
        {
          name: "asn:GeneralNames",
          args: asn1Schema.AsnConvert.parse(raw, asn1X509.GeneralNames),
          want: [
            { type: "dn", value: "CN=name, O=org" },
            { type: "dns", value: "some.com" }
          ],
        },
        {
          name: "asn:GeneralName[]",
          args: asn1Schema.AsnConvert.parse(raw, asn1X509.GeneralNames).map(o => o),
          want: [
            { type: "dn", value: "CN=name, O=org" },
            { type: "dns", value: "some.com" }
          ],
        },
        {
          name: "BufferSource",
          args: raw,
          want: [
            { type: "dn", value: "CN=name, O=org" },
            { type: "dns", value: "some.com" }
          ],
        },
      ];

    for (const t of tests) {
      it(t.name, () => {
        const obj = new x509.GeneralNames(t.args as any);
        assert.deepStrictEqual(obj.toJSON(), t.want);
      });
    }

  });

  context("toString", () => {
    const tests: {
      name: string;
      args: x509.JsonGeneralNames;
      want: string;
    }[] = [
        {
          name: "list of names",
          args: [
            { type: "dn", value: "CN=name,O=org" },
            { type: "email", value: "some@email.com" },
            { type: "dns", value: "some.com" },
            { type: "email", value: "some2@email.com" },
          ],
          want: "GeneralNames:\n  DN: CN=name, O=org\n  Email: some@email.com\n  Email: some2@email.com\n  DNS: some.com",
        },
      ];
    for (const t of tests) {
      it(t.name, () => {
        const name = new x509.GeneralNames(t.args);
        const text = name.toString("text");
        assert.strictEqual(text, t.want);
      });
    }
  });

});