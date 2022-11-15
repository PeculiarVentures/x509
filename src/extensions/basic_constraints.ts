import { AsnConvert } from "@peculiar/asn1-schema";
import { BasicConstraints as AsnBasicConstraints, id_ce_basicConstraints } from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { TextObject } from "../text_converter";

/**
 * Represents the Basic Constraints certificate extension
 */
export class BasicConstraintsExtension extends Extension {

  public static override NAME = "Basic Constraints";

  /**
   * Indicates whether the certified public key may be used
   * to verify certificate signatures
   */
  public readonly ca: boolean;

  /**
   * Gets a maximum number of non-self-issued intermediate certificates that may
   * follow this certificate in a valid certification path
   */
  public readonly pathLength?: number;

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param ca
   * @param pathLength
   * @param critical
   */
  public constructor(ca: boolean, pathLength?: number, critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0]);

      const value = AsnConvert.parse(this.value, AsnBasicConstraints);
      this.ca = value.cA;
      this.pathLength = value.pathLenConstraint;
    } else {
      const value = new AsnBasicConstraints({
        cA: args[0],
        pathLenConstraint: args[1],
      });
      super(id_ce_basicConstraints, args[2], AsnConvert.serialize(value));

      this.ca = args[0];
      this.pathLength = args[1];
    }
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    if (this.ca) {
      obj["CA"] = this.ca;
    }
    if (this.pathLength !== undefined) {
      obj["Path Length"] = this.pathLength;
    }

    return obj;
  }

}