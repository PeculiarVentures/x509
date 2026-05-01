import * as bytes from "@peculiar/utils/bytes";
import {
  hex, base64, base64url, binary,
} from "@peculiar/utils/encoding";
import { AsnData, AsnDataStringFormat } from "./asn_data";
import { PemConverter } from "./pem_converter";

export type AsnExportType = "pem" | AsnDataStringFormat;

export type AsnEncodedType = bytes.BufferSourceLike | string;

export abstract class PemData<T> extends AsnData<T> {
  public static isAsnEncoded(data: any): data is AsnEncodedType {
    return bytes.isBufferSource(data) || typeof data === "string";
  }

  /**
   * Converts encoded raw to ArrayBuffer. Supported formats are HEX, DER, Base64, Base64Url, PEM
   * @param raw Encoded data
   */
  public static toArrayBuffer(raw: bytes.BufferSourceLike | string): ArrayBuffer {
    if (typeof raw === "string") {
      if (PemConverter.isPem(raw)) {
        return PemConverter.decode(raw)[0];
      } else if (hex.is(raw)) {
        return bytes.toArrayBuffer(hex.decode(raw));
      } else if (base64.is(raw)) {
        return bytes.toArrayBuffer(base64.decode(raw));
      } else if (base64url.is(raw)) {
        return bytes.toArrayBuffer(base64url.decode(raw));
      } else {
        throw new TypeError("Unsupported format of 'raw' argument. Must be one of DER, PEM, HEX, Base64, or Base4Url");
      }
    } else {
      // Check if it looks like DER (starts with 0x30) to avoid slow string conversion
      // for large buffers
      const buffer = bytes.toUint8Array(raw);
      if (buffer.length > 0 && buffer[0] === 0x30) {
        return bytes.toArrayBuffer(raw);
      }

      const stringRaw = binary.encode(raw);
      if (PemConverter.isPem(stringRaw)) {
        return PemConverter.decode(stringRaw)[0];
      } else if (hex.is(stringRaw)) {
        return bytes.toArrayBuffer(hex.decode(stringRaw));
      } else if (base64.is(stringRaw)) {
        return bytes.toArrayBuffer(base64.decode(stringRaw));
      } else if (base64url.is(stringRaw)) {
        return bytes.toArrayBuffer(base64url.decode(stringRaw));
      }

      throw new TypeError("Unsupported format of 'raw' argument. Must be one of DER, PEM, HEX, Base64, or Base4Url");
    }
  }

  /**
   * PEM tag
   */
  protected abstract readonly tag: string;

  /**
   * Creates a new instance
   * @param raw Encoded buffer (DER, PEM, HEX, Base64, Base64Url)
   * @param type ASN.1 convertible class for `@peculiar/asn1-schema` schema
   */
  public constructor(raw: AsnEncodedType, type: new () => T);
  /**
   * Creates a new instance
   * @param asn ASN.1 object
   */
  public constructor(asn: T);
  public constructor(...args: any[]) {
    if (PemData.isAsnEncoded(args[0])) {
      super(PemData.toArrayBuffer(args[0]), args[1]);
    } else {
      super(args[0]);
    }
  }

  /**
   * Returns encoded object in PEM format
   */
  public toString(): string;
  /**
   * Returns encoded object in selected format
   * @param format hex, base64, base64url, pem, asn, text
   */
  public toString(format: AsnExportType): string;
  public override toString(format: AsnExportType = "pem") {
    switch (format) {
      case "pem":
        return PemConverter.encode(this.rawData, this.tag);
      default:
        return super.toString(format);
    }
  }
}
