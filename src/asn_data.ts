/* eslint-disable @typescript-eslint/member-delimiter-style */

import { AsnConvert } from "@peculiar/asn1-schema";
import { BufferSourceConverter, Convert, isEqual } from "pvtsutils";
import { TextConverter, TextObject, TextObjectConvertible } from "./text_converter";

export type AsnDataStringFormat = "asn" | "text" | "hex" | "base64" | "base64url";

/**
 * Represents an ASN.1 data
 */
export abstract class AsnData<T> implements TextObjectConvertible {
  public static NAME = "ASN";

  /**
   * Gets a DER encoded buffer
   */
  public readonly rawData: ArrayBuffer;

  /**
   * Creates a new instance
   * @param raw DER encoded buffer
   * @param type ASN.1 convertible class for `@peculiar/asn1-schema` schema
   */
  public constructor(raw: BufferSource, type: { new(): T; });
  /**
   * ASN.1 object
   * @param asn
   */
  public constructor(asn: T);
  public constructor(...args: any[]) {
    if (args.length === 1) {
      // asn
      const asn: T = args[0];
      this.rawData = AsnConvert.serialize(asn);
      this.onInit(asn);
    } else {
      // raw, type
      const asn = AsnConvert.parse<T>(args[0], args[1]);
      this.rawData = BufferSourceConverter.toArrayBuffer(args[0]);
      this.onInit(asn);
    }
  }

  /**
   * Occurs on instance initialization
   * @param asn ASN.1 object
   */
  protected abstract onInit(asn: T): void;

  /**
   * Returns `true` if ASN.1 data is equal to another ASN.1 data, otherwise `false`
   * @param data Any data
   */
  public equal(data: any): data is this {
    if (data instanceof AsnData) {
      return isEqual(data.rawData, this.rawData);
    }

    return false;
  }

  public toString(format: AsnDataStringFormat = "text"): string {
    switch (format) {
      case "asn":
        return AsnConvert.toString(this.rawData);
      case "text":
        return TextConverter.serialize(this.toTextObject());
      case "hex":
        return Convert.ToHex(this.rawData);
      case "base64":
        return Convert.ToBase64(this.rawData);
      case "base64url":
        return Convert.ToBase64Url(this.rawData);
      default:
        throw TypeError("Argument 'format' is unsupported value");
    }
  }

  protected getTextName(): string {
    const constructor = this.constructor as typeof AsnData;

    return constructor.NAME;
  }

  public toTextObject(): TextObject {
    const obj = this.toTextObjectEmpty();

    obj[""] = this.rawData;

    return obj;
  }

  protected toTextObjectEmpty(value?: string): TextObject {
    return new TextObject(this.getTextName(), {}, value);
  }

}