import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import * as bytes from "@peculiar/utils/bytes";
import { hex } from "@peculiar/utils/encoding";

import { Extension } from "../extension";
import { cryptoProvider } from "../provider";
import { PublicKey, PublicKeyType } from "../public_key";
import { TextObject } from "../text_converter";

/**
 * Represents the Subject Key Identifier certificate extension
 */
export class SubjectKeyIdentifierExtension extends Extension {
  public static override NAME = "Subject Key Identifier";

  /**
   * Creates subject key identifier extension from public key data
   * @param publicKey Public key data
   * @param critical Indicates where extension is critical. Default is `false`
   * @param crypto WebCrypto provider. Default is from CryptoProvider
   */
  public static async create(
    publicKey: PublicKeyType,
    critical = false,
    crypto = cryptoProvider.get(),
  ) {
    const key = await PublicKey.create(publicKey, crypto);
    const id = await key.getKeyIdentifier(crypto);

    return new SubjectKeyIdentifierExtension(hex.encode(id), critical);
  }

  /**
   * Gets hexadecimal representation of key identifier
   */
  public readonly keyId: string;

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: bytes.BufferSourceLike);
  /**
   * Creates a new instance
   * @param keyId Hexadecimal representation of key identifier
   * @param critical Indicates where extension is critical. Default is `false`
   */
  public constructor(keyId: string, critical?: boolean);
  public constructor(...args: any[]) {
    if (bytes.isBufferSource(args[0])) {
      super(args[0] as bytes.BufferSourceLike);

      const value = AsnConvert.parse(this.value, asn1X509.SubjectKeyIdentifier);
      this.keyId = hex.encode(value);
    } else {
      const identifier = typeof args[0] === "string"
        ? hex.decode(args[0])
        : args[0];
      const value = new asn1X509.SubjectKeyIdentifier(identifier);
      super(asn1X509.id_ce_subjectKeyIdentifier, args[1], AsnConvert.serialize(value));

      this.keyId = hex.encode(identifier);
    }
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    const asn = AsnConvert.parse(this.value, asn1X509.SubjectKeyIdentifier);

    obj[""] = asn;

    return obj;
  }
}
