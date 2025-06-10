import { describe, it, expect } from "vitest";
import { Attribute, TextObject } from "../src";

describe("Attribute", function () {
  describe("#toTextObject()", function () {
    it("should return a TextObject with correct values", function () {
      const attribute = new Attribute("1.2.3", [new ArrayBuffer(8)]);
      const textObject = attribute.toTextObject();

      expect(textObject[TextObject.NAME]).toBe("1.2.3");
      expect(Array.isArray(textObject.Value)).toBeTruthy();
      if (Array.isArray(textObject.Value)) {
        expect(textObject.Value.length).toBe(1);
        expect(textObject.Value[0] instanceof TextObject).toBeTruthy();
      }
    });
  });

  describe("#toTextObjectWithoutValue()", function () {
    it("should return a TextObject without the Value property", function () {
      const attribute = new Attribute("1.2.3", [new ArrayBuffer(8)]);
      const textObject = attribute.toTextObjectWithoutValue();

      expect(textObject[TextObject.NAME]).toBe("1.2.3");
      expect(textObject.Value).toBe(undefined);
    });
  });
});