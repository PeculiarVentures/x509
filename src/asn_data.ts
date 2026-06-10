import { AsnConvert } from "@peculiar/asn1-schema";
import * as bytes from "@peculiar/utils/bytes";
import {
  hex, base64, base64url,
} from "@peculiar/utils/encoding";
import {
  TextConverter, TextObject, TextObjectConvertible,
} from "./text_converter";

export type AsnDataStringFormat = "asn" | "text" | "hex" | "base64" | "base64url";

/**
 * Represents an ASN.1 data
 */
export abstract class AsnData<T> implements TextObjectConvertible {
  public static NAME = "ASN";

  #rawData!: ArrayBuffer;

  /**
   * Gets a DER encoded buffer
   */
  public get rawData(): ArrayBuffer {
    if (!this.#rawData) {
      this.#rawData = AsnConvert.serialize(this.asn);
    }

    return this.#rawData;
  }

  /**
   * ASN.1 object
   */
  protected readonly asn: T;

  /**
   * Creates a new instance
   * @param raw DER encoded buffer
   * @param type ASN.1 convertible class for `@peculiar/asn1-schema` schema
   */
  public constructor(raw: bytes.BufferSourceLike, type: new () => T);
  /**
   * ASN.1 object
   * @param asn
   */
  public constructor(asn: T);
  public constructor(...args: any[]) {
    if (bytes.isBufferSource(args[0])) {
      // raw, type
      this.asn = AsnConvert.parse<T>(args[0], args[1]);
      this.#rawData = bytes.toArrayBuffer(args[0]);
      this.onInit(this.asn);
    } else {
      // asn
      this.asn = args[0];
      this.onInit(this.asn);
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
      return bytes.equal(data.rawData, this.rawData);
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
        return hex.encode(this.rawData);
      case "base64":
        return base64.encode(this.rawData);
      case "base64url":
        return base64url.encode(this.rawData);
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
