import * as assert from "node:assert";
import { Attribute, TextObject } from "../src";

context("Attribute", function () {
  context("#toTextObject()", function () {
    it("should return a TextObject with correct values", function () {
      const attribute = new Attribute("1.2.3", [new ArrayBuffer(8)]);
      const textObject = attribute.toTextObject();

      assert.strictEqual(textObject[TextObject.NAME], "1.2.3");
      assert.ok(Array.isArray(textObject.Value));
      assert.strictEqual(textObject.Value.length, 1);
      assert(textObject.Value[0] instanceof TextObject);
    });
  });

  context("#toTextObjectWithoutValue()", function () {
    it("should return a TextObject without the Value property", function () {
      const attribute = new Attribute("1.2.3", [new ArrayBuffer(8)]);
      const textObject = attribute.toTextObjectWithoutValue();

      assert.strictEqual(textObject[TextObject.NAME], "1.2.3");
      assert.strictEqual(textObject.Value, undefined);
    });
  });
});