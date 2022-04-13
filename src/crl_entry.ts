import { AsnConvert } from "@peculiar/asn1-schema";
import { RevokedCertificate } from "@peculiar/asn1-x509";
import { Extension } from "./extension";
import { ExtensionFactory } from "./extensions/extension_factory";
import { AsnEncodedType, PemData } from "./pem_data";
import { Convert } from "pvtsutils";

/**
 * Representation of CRLEntry
 */
export class CRLEntry extends PemData<RevokedCertificate> {
  protected readonly tag;

  /**
  * Gets a hexadecimal string of the serial number, the userCertificate
  */
  public serialNumber!: string;

  /**
  * Gets the revocation date
  */
  public revocationDate!: Date;

  /**
  * Gets crl entry extensions
  */
  public crlEntryExtensions!: Extension[];

  /**
   * Creates a new instance from ASN.1 RevokedCertificate object
   * @param asn ASN.1 RevokedCertificate object
   */
  public constructor(asn: RevokedCertificate);
  /**
   * Creates a new instance
   * @param raw Encoded buffer (DER, PEM, HEX, Base64, Base64Url)
   */
  public constructor(raw: AsnEncodedType);
  public constructor(param: AsnEncodedType | RevokedCertificate) {
    if (PemData.isAsnEncoded(param)) {
      super(param, RevokedCertificate);
    } else {
      super(param);
    }

    this.tag = "CRLEntry";
  }

  protected onInit(asn: RevokedCertificate) {
    this.serialNumber = Convert.ToHex(asn.userCertificate);
    const revocationDate = asn.revocationDate.utcTime || asn.revocationDate.generalTime;
    if (!revocationDate) {
      throw new Error("Cannot get 'revocationDate' value");
    }
    this.revocationDate = revocationDate;

    this.crlEntryExtensions = [];
    if (asn.crlEntryExtensions) {
      this.crlEntryExtensions = asn.crlEntryExtensions.map((o) =>
        ExtensionFactory.create(AsnConvert.serialize(o))
      );
    }
  }
}