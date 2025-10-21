import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { Extension } from "../extension";
import { GeneralNames } from "../general_name";
import { cryptoProvider } from "../provider";
import { PublicKey, PublicKeyType } from "../public_key";
import { TextObject } from "../text_converter";

export interface CertificateIdentifier {
  /**
   * Name
   */
  name: asn1X509.GeneralName[] | asn1X509.GeneralNames | GeneralNames;
  /**
   * Hexadecimal string
   */
  serialNumber: string;
}

/**
 * Represents the Authority Key Identifier certificate extension
 */
export class AuthorityKeyIdentifierExtension extends Extension {
  public static override NAME = "Authority Key Identifier";

  /**
   * Creates authority key identifier extension from certificate identifier
   * @param certId Certificate identifier
   * @param critical Indicates where extension is critical. Default is `false`
   * @param crypto WebCrypto provider. Default is from CryptoProvider
   */
  public static async create(
    certId: CertificateIdentifier,
    critical?: boolean,
    crypto?: Crypto
  ): Promise<AuthorityKeyIdentifierExtension>;
  /**
   * Creates authority key identifier extension from public key data
   * @param publicKey Public key data
   * @param critical Indicates where extension is critical. Default is `false`
   * @param crypto WebCrypto provider. Default is from CryptoProvider
   */
  public static async create(
    publicKey: PublicKeyType,
    critical?: boolean,
    crypto?: Crypto
  ): Promise<AuthorityKeyIdentifierExtension>;
  public static async create(
    param: PublicKeyType | CertificateIdentifier,
    critical = false,
    crypto = cryptoProvider.get(),
  ) {
    if ("name" in param && "serialNumber" in param) {
      return new AuthorityKeyIdentifierExtension(param, critical);
    }
    const key = await PublicKey.create(param, crypto);
    const id = await key.getKeyIdentifier(crypto);

    return new AuthorityKeyIdentifierExtension(Convert.ToHex(id), critical);
  }

  /**
   * Gets a hexadecimal representation of key identifier
   */
  public keyId?: string;

  /**
   * Gets a certificate identifier in the issuer name and serial number
   */
  public certId?: CertificateIdentifier;

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param identifier Hexadecimal representation of key identifier
   * @param critical Indicates where extension is critical. Default is `false`
   */
  public constructor(identifier: string, critical?: boolean);
  /**
   * Creates a new instance
   * @param id Certificate identifier in the issuer name and serial number
   * @param critical Indicates where extension is critical. Default is `false`
   */
  public constructor(id: CertificateIdentifier, critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0] as BufferSource);
    } else if (typeof args[0] === "string") {
      const value = new asn1X509.AuthorityKeyIdentifier(
        { keyIdentifier: new asn1X509.KeyIdentifier(Convert.FromHex(args[0])) },
      );
      super(asn1X509.id_ce_authorityKeyIdentifier, args[1], AsnConvert.serialize(value));
    } else {
      const certId = args[0] as CertificateIdentifier;
      const certIdName = certId.name instanceof GeneralNames
        ? AsnConvert.parse(certId.name.rawData, asn1X509.GeneralNames)
        : certId.name;
      const value = new asn1X509.AuthorityKeyIdentifier({
        authorityCertIssuer: certIdName,
        authorityCertSerialNumber: Convert.FromHex(certId.serialNumber),
      });
      super(asn1X509.id_ce_authorityKeyIdentifier, args[1], AsnConvert.serialize(value));
    }
  }

  protected onInit(asn: asn1X509.Extension) {
    super.onInit(asn);

    const aki = AsnConvert.parse(asn.extnValue, asn1X509.AuthorityKeyIdentifier);
    if (aki.keyIdentifier) {
      this.keyId = Convert.ToHex(aki.keyIdentifier);
    }

    if (aki.authorityCertIssuer || aki.authorityCertSerialNumber) {
      this.certId = {
        name: aki.authorityCertIssuer || [],
        serialNumber: aki.authorityCertSerialNumber ? Convert.ToHex(aki.authorityCertSerialNumber) : "",
      };
    }
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    const asn = AsnConvert.parse(this.value, asn1X509.AuthorityKeyIdentifier);

    if (asn.authorityCertIssuer) {
      obj["Authority Issuer"] = new GeneralNames(asn.authorityCertIssuer).toTextObject();
    }
    if (asn.authorityCertSerialNumber) {
      obj["Authority Serial Number"] = asn.authorityCertSerialNumber;
    }
    if (asn.keyIdentifier) {
      obj[""] = asn.keyIdentifier;
    }

    return obj;
  }
}
