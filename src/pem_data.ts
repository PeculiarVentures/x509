import { BufferSourceConverter, Convert } from "pvtsutils";
import { AsnData, AsnDataStringFormat } from "./asn_data";
import { PemConverter } from "./pem_converter";

export type AsnExportType = "pem" | AsnDataStringFormat;

export type AsnEncodedType = BufferSource | string;

export abstract class PemData<T> extends AsnData<T> {

  public static isAsnEncoded(data: any): data is AsnEncodedType {
    return BufferSourceConverter.isBufferSource(data) || typeof data === "string";
  }

  /**
   * Converts encoded raw to ArrayBuffer. Supported formats are HEX, DER, Base64, Base64Url, PEM
   * @param raw Encoded data
   */
  public static toArrayBuffer(raw: BufferSource | string): ArrayBuffer {
    if (typeof raw === "string") {
      if (PemConverter.isPem(raw)) {
        return PemConverter.decode(raw)[0];
      } else if (Convert.isHex(raw)) {
        return Convert.FromHex(raw);
      } else if (Convert.isBase64(raw)) {
        return Convert.FromBase64(raw);
      } else if (Convert.isBase64Url(raw)) {
        return Convert.FromBase64Url(raw);
      } else {
        throw new TypeError("Unsupported format of 'raw' argument. Must be one of DER, PEM, HEX, Base64, or Base4Url");
      }
    } else {
      const stringRaw = Convert.ToBinary(raw);
      if (PemConverter.isPem(stringRaw)) {
        return PemConverter.decode(stringRaw)[0];
      } else if (Convert.isHex(stringRaw)) {
        return Convert.FromHex(stringRaw);
      } else if (Convert.isBase64(stringRaw)) {
        return Convert.FromBase64(stringRaw);
      } else if (Convert.isBase64Url(stringRaw)) {
        return Convert.FromBase64Url(stringRaw);
      }

      return BufferSourceConverter.toArrayBuffer(raw);
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
  public constructor(raw: AsnEncodedType, type: { new(): T; });
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