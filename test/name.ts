import * as assert from "assert";
import * as asn1Schema from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import * as x509 from "../src";
import { Convert } from "pvtsutils";

context("Name", () => {

  function assertName(name: asn1X509.Name, text: string) {
    // serialize
    const value = new x509.Name(name).toString();
    assert.strictEqual(value, text);

    // parse
    const name2 = new x509.Name(text);
    assert.strictEqual(name2.toString(), text);
  }

  it("Simple list of RDNs (joined by comma)", () => {
    const name = new asn1X509.Name([
      new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "2.5.4.3", value: new asn1X509.AttributeValue({ printableString: "Common Name" }) })]),
      new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "2.5.4.6", value: new asn1X509.AttributeValue({ printableString: "RU" }) })])
    ]);

    assertName(name, "CN=Common Name, C=RU");
  });

  it("Simple list of DNs (joined by +)", () => {
    const name = new asn1X509.Name([
      new asn1X509.RelativeDistinguishedName([
        new asn1X509.AttributeTypeAndValue({ type: "2.5.4.3", value: new asn1X509.AttributeValue({ printableString: "Common Name" }) }),
        new asn1X509.AttributeTypeAndValue({ type: "2.5.4.6", value: new asn1X509.AttributeValue({ printableString: "RU" }) })]),
    ]);

    assertName(name, "CN=Common Name+C=RU");
  });

  it("Hexadecimal representation", () => {
    const name = new asn1X509.Name([
      new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ anyValue: new Uint8Array([0x04, 0x02, 0x48, 0x69]).buffer }) })]),
    ]);

    assertName(name, "1.2.3.4.5=#04024869");
  });

  context("Escaped chars", () => {

    it("# character at the beginning", () => {
      const name = new asn1X509.Name([
        new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ printableString: "#tag" }) })]),
      ]);

      assertName(name, "1.2.3.4.5=\\#tag");
    });

    it("space character at the beginning", () => {
      const name = new asn1X509.Name([
        new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ printableString: " tag" }) })]),
      ]);

      assertName(name, "1.2.3.4.5=\\ tag");
    });

    it("space character at the end", () => {
      const name = new asn1X509.Name([
        new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ printableString: "tag " }) })]),
      ]);

      assertName(name, "1.2.3.4.5=tag\\ ");
    });

    it("special characters", () => {
      const name = new asn1X509.Name([
        new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ printableString: ",+\"\\<>;" }) })]),
      ]);

      assertName(name, "1.2.3.4.5=\\,\\+\\\"\\\\\\<\\>\\;");
    });

    it("unknown characters", () => {
      const name = new asn1X509.Name([
        new asn1X509.RelativeDistinguishedName([new asn1X509.AttributeTypeAndValue({ type: "1.2.3.4.5", value: new asn1X509.AttributeValue({ printableString: "Hello\nworld" }) })]),
      ]);

      assertName(name, "1.2.3.4.5=Hello\\0Aworld");
    });

    it("parse quoted value", () => {
      const text = "CN=\"here is a test message with \\\",\\\" character\"+CN=It includes \\< \\> \\+ escaped characters\\ ";
      const name = new x509.Name(text);
      assert.strictEqual(name.toString(), "CN=here is a test message with \\\"\\,\\\" character+CN=It includes \\< \\> \\+ escaped characters\\ ");
    });

  });

  it("json", () => {
    const text = "CN=name1, CN=name2+CN=name3+E=some@email.com, 1.2.3.4.5=#04020102+DC=some.com";
    const name = new x509.Name(text);

    const json: x509.JsonName = [
      { CN: ["name1"] },
      { CN: ["name2", "name3"], E: ["some@email.com"] },
      { "1.2.3.4.5": ["#04020102"], DC: ["some.com"] },
    ];
    assert.deepStrictEqual(name.toJSON(), json);

    const name2 = new x509.Name(json);
    assert.strictEqual(name2.toString(), text);

    assert.strictEqual(Convert.ToHex(name.toArrayBuffer()), "3071310e300c060355040313056e616d65313139300c060355040313056e616d6532300c060355040313056e616d6533301b06092a864886f70d010901160e736f6d6540656d61696c2e636f6d3124300a06042a030405040201023016060a0992268993f22c6401191608736f6d652e636f6d");
  });

  it("parse with odd , marks", () => {
    const text = "  ,  , ,  CN=Some Name, O=Peculiar Ventures\\, LLC, O=\"Peculiar Ventures, LLC\", CN=name2+O=Test+CN=name3+E=some@email.com, 1.2.3.4.5=#04020102+DC=some.com,, , ";
    const name = new x509.Name(text);

    assert.strictEqual(name.toString(), "CN=Some Name, O=Peculiar Ventures\\, LLC, O=Peculiar Ventures\\, LLC, CN=name2+O=Test+CN=name3+E=some@email.com, 1.2.3.4.5=#04020102+DC=some.com");
  });

  it("extra names", () => {
    const text = "Email=some@email.com, IP=192.168.0.1, GUID={8ee13e53-2c1c-42bb-8df7-39927c0bdbb6}";
    const name = new x509.Name(text, {
      "Email": "1.2.3.4.5.1",
      "IP": "1.2.3.4.5.2",
      "GUID": "1.2.3.4.5.3",
    });

    assert.strictEqual(Convert.ToHex(name.toArrayBuffer()), "30663119301706052a03040501130e736f6d6540656d61696c2e636f6d3116301406052a03040502130b3139322e3136382e302e313131302f06052a0304050313267b38656531336535332d326331632d343262622d386466372d3339393237633062646262367d");
    assert.deepStrictEqual(name.toJSON(), [
      { "Email": ["some@email.com"] },
      { "IP": ["192.168.0.1"] },
      { "GUID": ["{8ee13e53-2c1c-42bb-8df7-39927c0bdbb6}"] },
    ]);
  });

  it("use Utf8String for Common name", () => {
    const asnName = new asn1X509.Name([
      new asn1X509.RelativeDistinguishedName([
        new asn1X509.AttributeTypeAndValue({
          type: "2.5.4.3",
          value: new asn1X509.AttributeValue({
            utf8String: "Some name",
          })
        })
      ]),
    ]);

    const name = new x509.Name(asn1Schema.AsnConvert.serialize(asnName));
    assert.strictEqual(name.toString(), "CN=Some name");

    assert.strictEqual(Convert.ToHex(name.toArrayBuffer()), "30143112301006035504030c09536f6d65206e616d65");
  });

  context("get thumbprint", () => {

    it("default", async () => {
      const name = new x509.Name("CN=Some");
      const hash = await name.getThumbprint();
      assert.strictEqual(Convert.ToHex(hash), "4c19048809647a5cd443000c4b1b9d174164bf03");
    });

    it("SHA-256", async () => {
      const name = new x509.Name("CN=Some");
      const hash = await name.getThumbprint("SHA-256");
      assert.strictEqual(Convert.ToHex(hash), "38e29244d77fb9f2735d034aba8a6ecaf5070f5fe18efb050424f96cecb0db03");
    });

  });

  context("getField", () => {

    const dn = "CN=n1+CN=n2, CN=n3+O=o1, O=o2";

    const tests: {
      name: string;
      args: string;
      want: string[];
    }[] = [
        {
          name: "use id:2.5.4.3",
          args: "2.5.4.3",
          want: ["n1", "n2", "n3"],
        },
        {
          name: "use name:CN",
          args: "CN",
          want: ["n1", "n2", "n3"],
        },
        {
          name: "use missed name:L",
          args: "L",
          want: [],
        },
        {
          name: "use unknown name:UNKNOWN",
          args: "UNKNOWN",
          want: [],
        },
      ];
    for (const t of tests) {
      it(t.name, () => {
        const name = new x509.Name(dn);
        const res = name.getField(t.args);
        assert.deepStrictEqual(res, t.want);
      });
    }

  });

});

context("NameIdentifier", () => {

  context("findId", () => {

    const names = new x509.NameIdentifier({
      "2.5.4.3": "CN",
    });

    const tests: {
      name: string;
      args: string;
      want: string | null;
    }[] = [
        {
          name: "existing name",
          args: "CN",
          want: "2.5.4.3",
        },
        {
          name: "missed name",
          args: "O",
          want: null,
        },
        {
          name: "id instead of name",
          args: "2.5.4.10",
          want: "2.5.4.10",
        },
      ];
    for (const t of tests) {
      it(t.name, () => {
        const name = names.findId(t.args);
        assert.strictEqual(name, t.want);
      });
    }

  });

});