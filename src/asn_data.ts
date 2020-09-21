/* eslint-disable @typescript-eslint/member-delimiter-style */

import { AsnConvert } from "@peculiar/asn1-schema";
import { BufferSourceConverter } from "pvtsutils";

/**
 * Represents an ASN.1 data
 */
export abstract class AsnData<T> {
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
}