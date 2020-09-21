import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { Extension } from "../extension";
import { CryptoProvider, cryptoProvider } from "../provider";
import { X509Certificate } from "../x509_cert";

export interface CertificateIdentifier {
  /**
   * Name
   */
  name: asn1X509.GeneralName[];
  /**
   * Hexadecimal string
   */
  serialNumber: string;
}

/**
 * Represents the Authority Key Identifier certificate extension
 */
export class AuthorityKeyIdentifierExtension extends Extension {

  /**
   * Creates authority key identifier extension from certificate
   * @param cert Certificate
   * @param critical Indicates where extension is critical. Default is `false`
   * @param crypto WebCrypto provider. Default is from CryptoProvider
   */
  public static async create(cert: X509Certificate, critical?: boolean, crypto?: Crypto): Promise<AuthorityKeyIdentifierExtension>;
  /**
   * Creates authority key identifier extension from certificate identifier
   * @param certId Certificate identifier
   * @param critical Indicates where extension is critical. Default is `false`
   * @param crypto WebCrypto provider. Default is from CryptoProvider
   */
  public static async create(certId: CertificateIdentifier, critical?: boolean, crypto?: Crypto): Promise<AuthorityKeyIdentifierExtension>;
  /**
   * Creates authority key identifier extension from CryptoKey
   * @param publicKey Public CryptoKey
   * @param critical Indicates where extension is critical. Default is `false`
   * @param crypto WebCrypto provider. Default is from CryptoProvider
   */
  public static async create(publicKey: CryptoKey, critical?: boolean, crypto?: Crypto): Promise<AuthorityKeyIdentifierExtension>;
  public static async create(param: CryptoKey | CertificateIdentifier | X509Certificate, critical = false, crypto = cryptoProvider.get()) {
    if (param instanceof X509Certificate || CryptoProvider.isCryptoKey(param)) {
      const publicKey = param instanceof X509Certificate ? await param.publicKey.export(crypto) : param;
      const spki = await crypto.subtle.exportKey("spki", publicKey);
      const ski = await crypto.subtle.digest("SHA-1", spki);
      return new AuthorityKeyIdentifierExtension(Convert.ToHex(ski), critical);
    } else {
      return new AuthorityKeyIdentifierExtension(param, critical);
    }
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
      super(args[0]);
    } else if (typeof args[0] === "string") {
      const value = new asn1X509.AuthorityKeyIdentifier({ keyIdentifier: new OctetString(Convert.FromHex(args[0])) });
      super(asn1X509.id_ce_authorityKeyIdentifier, args[1], AsnConvert.serialize(value));
    } else {
      const certId = args[0] as CertificateIdentifier;
      const value = new asn1X509.AuthorityKeyIdentifier({
        authorityCertIssuer: certId.name,
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

    if (aki.authorityCertIssuer && aki.authorityCertSerialNumber) {
      this.certId = {
         name: aki.authorityCertIssuer,
         serialNumber: Convert.ToHex(aki.authorityCertSerialNumber),
      }
    }
  }

}
