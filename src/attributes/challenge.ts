import { AsnConvert } from "@peculiar/asn1-schema";
import * as asnX509 from "@peculiar/asn1-x509";
import * as asnPkcs9 from "@peculiar/asn1-pkcs9";
import { BufferSourceConverter } from "pvtsutils";
import { Attribute } from "../attribute";
import { TextObject } from "../text_converter";

export class ChallengePasswordAttribute extends Attribute {

  public static override NAME = "Challenge Password";

  public password: string;

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param value
   */
  public constructor(value: string);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0]);
    } else {
      const value = new asnPkcs9.ChallengePassword({
        printableString: args[0],
      });
      super(asnPkcs9.id_pkcs9_at_challengePassword, [AsnConvert.serialize(value)]);
    }

    this.password ??= "";
  }

  protected onInit(asn: asnX509.Attribute): void {
    super.onInit(asn);

    if (this.values[0]) {
      const value = AsnConvert.parse(this.values[0], asnPkcs9.ChallengePassword);
      this.password = value.toString();
    }
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    obj[TextObject.VALUE] = this.password;

    return obj;
  }

}