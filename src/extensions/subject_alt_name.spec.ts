import { describe, it, expect } from "vitest";
import { Convert } from "pvtsutils";
import * as x509 from "../index";

describe("crypto", () => {
  describe("Extensions", () => {
    it("Subject Alternative Name", () => {
      const hex =
        "3081a80603551d110481a030819d820d736f6d652e6e616d652e636f6d820e736f6d65322e6e616d652e636f6d81126d6963726f7368696e65406d61696c2e7275a01f06092b0601040182371901a0120410533ee18e1c2cbb428df739927c0bdbb687040a0109058613687474703a2f2f736f6d652e75726c2e636f6d861666696c653a2f2f2f736f6d652f66696c652f70617468a014060a2b060104018237140203a0060c0475736572";
      const san = new x509.SubjectAlternativeNameExtension(Convert.FromHex(hex));
      const json = san.names.toJSON();
      expect(json).toEqual([
        {
          type: "dns",
          value: "some.name.com",
        },
        {
          type: "dns",
          value: "some2.name.com",
        },
        {
          type: "email",
          value: "microshine@mail.ru",
        },
        {
          type: "guid",
          value: "8ee13e53-2c1c-42bb-8df7-39927c0bdbb6",
        },
        {
          type: "ip",
          value: "10.1.9.5",
        },
        {
          type: "url",
          value: "http://some.url.com",
        },
        {
          type: "url",
          value: "file:///some/file/path",
        },
        {
          type: "upn",
          value: "user",
        },
      ]);

      const san2 = new x509.SubjectAlternativeNameExtension(json, san.critical);
      const hex2 = Convert.ToHex(san2.rawData);

      expect(hex2).toBe(hex);
    });
  });
});
