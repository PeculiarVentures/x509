import { AsnConvert } from "@peculiar/asn1-schema";
import * as asnX509 from "@peculiar/asn1-x509";
import * as asnPkcs9 from "@peculiar/asn1-pkcs9";
import * as bytes from "@peculiar/utils/bytes";
import { Attribute } from "../attribute";
import { TextObject } from "../text_converter";

export class ChallengePasswordAttribute extends Attribute {
  public static override NAME = "Challenge Password";

  declare public password: string;

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: bytes.BufferSourceLike);
  /**
   * Creates a new instance
   * @param value
   */
  public constructor(value: string);
  public constructor(...args: any[]) {
    if (bytes.isBufferSource(args[0])) {
      super(args[0] as bytes.BufferSourceLike);
    } else {
      const value = new asnPkcs9.ChallengePassword({ printableString: args[0] });
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
