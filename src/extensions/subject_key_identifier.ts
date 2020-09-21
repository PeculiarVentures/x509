import { AsnConvert } from "@peculiar/asn1-schema";
import { id_ce_subjectKeyIdentifier, SubjectKeyIdentifier } from "@peculiar/asn1-x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { Extension } from "../extension";
import { cryptoProvider } from "../provider";

/**
 * Represents the Subject Key Identifier certificate extension
 */
export class SubjectKeyIdentifierExtension extends Extension {

  /**
   * Creates subject key identifier extension from CryptoKey
   * @param publicKey Public CryptoKey
   * @param critical Indicates where extension is critical. Default is `false`
   * @param crypto WebCrypto provider. Default is from CryptoProvider
   */
  public static async create(publicKey: CryptoKey, critical = false, crypto = cryptoProvider.get()) {
    const spki = await crypto.subtle.exportKey("spki", publicKey);
    const ski = await crypto.subtle.digest("SHA-1", spki);
    return new SubjectKeyIdentifierExtension(Convert.ToHex(ski), critical);
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

      const value = AsnConvert.parse(this.value, SubjectKeyIdentifier);
      this.keyId = Convert.ToHex(value);
    } else {
      const identifier = typeof args[0] === "string"
        ? Convert.FromHex(args[0])
        : args[0];
      const value = new SubjectKeyIdentifier(identifier);
      super(id_ce_subjectKeyIdentifier, args[1], AsnConvert.serialize(value));

      this.keyId = Convert.ToHex(identifier);
    }
  }
}