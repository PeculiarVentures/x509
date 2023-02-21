import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
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
   * Creates subject key identifier extension from CryptoKey
   * @param publicKey Public CryptoKey
   * @param critical Indicates where extension is critical. Default is `false`
   * @param crypto WebCrypto provider. Default is from CryptoProvider
   */
  public static async create(publicKey: PublicKeyType, critical = false, crypto = cryptoProvider.get()) {
    let spki: BufferSource;
    if (publicKey instanceof PublicKey) {
      spki = publicKey.rawData;
    } else if ("publicKey" in publicKey) {
      spki = publicKey.publicKey.rawData;
    } else if (BufferSourceConverter.isBufferSource(publicKey)) {
      spki = publicKey;
    } else {
      spki = await crypto.subtle.exportKey("spki", publicKey);
    }

    const key = new PublicKey(spki);
    const id = await key.getKeyIdentifier(crypto);

    return new SubjectKeyIdentifierExtension(Convert.ToHex(id), critical);
  }

  /**
   * Gets hexadecimal representation of key identifier
   */
  public readonly keyId: string;

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param keyId Hexadecimal representation of key identifier
   * @param critical Indicates where extension is critical. Default is `false`
   */
  public constructor(keyId: string, critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0]);

      const value = AsnConvert.parse(this.value, asn1X509.SubjectKeyIdentifier);
      this.keyId = Convert.ToHex(value);
    } else {
      const identifier = typeof args[0] === "string"
        ? Convert.FromHex(args[0])
        : args[0];
      const value = new asn1X509.SubjectKeyIdentifier(identifier);
      super(asn1X509.id_ce_subjectKeyIdentifier, args[1], AsnConvert.serialize(value));

      this.keyId = Convert.ToHex(identifier);
    }
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    const asn = AsnConvert.parse(this.value, asn1X509.SubjectKeyIdentifier);

    obj[""] = asn;

    return obj;
  }

}