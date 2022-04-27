import { AsnConvert } from "@peculiar/asn1-schema";
import { CertificateIssuer, CRLReason, id_ce_certificateIssuer, id_ce_cRLReasons, id_ce_invalidityDate, InvalidityDate, Name, RevokedCertificate, Time } from "@peculiar/asn1-x509";
import { Extension } from "./extension";
import { ExtensionFactory } from "./extensions/extension_factory";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { AsnData } from "./asn_data";

/**
 * Reason Code
 * The reasonCode is a non-critical CRL entry extension that identifies
 * the reason for the certificate revocation.
 */
export enum X509CrlReason {
  unspecified = 0,
  keyCompromise = 1,
  cACompromise = 2,
  affiliationChanged = 3,
  superseded = 4,
  cessationOfOperation = 5,
  certificateHold = 6,
  removeFromCRL = 8,
  privilegeWithdrawn = 9,
  aACompromise = 10
}

/**
  * Representation of X509CrlEntry
  */
export class X509CrlEntry extends AsnData<RevokedCertificate> {
  /**
   * Gets a hexadecimal string of the serial number, the userCertificate
   */
  public serialNumber!: string;

  /**
   * Gets the revocation date
   */
  public revocationDate!: Date;

  /**
   * Gets the reason code
   */
  public reason?: X509CrlReason;

  /**
   * Gets the invalidity Date
   * The invalidity date is a non-critical CRL entry extension that
   * provides the date on which it is known or suspected that the private
   * key was compromised or that the certificate otherwise became invalid.
   */
  public invalidity?: Date;

  /**
   * Gets crl entry extensions
   */
  public extensions!: Extension[];

  /**
   * Creates a new instance from DER encoded Buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param serialNumber Serial number of certificate
   * @param revocationDate Revocation date
   * @param extensions List of crl extensions
   */
  public constructor(serialNumber: string, revocationDate: Date, extensions: Extension[]);
  public constructor(...args: any[]) {
    let raw: ArrayBuffer;
    if (BufferSourceConverter.isBufferSource(args[0])) {
      raw = BufferSourceConverter.toArrayBuffer(args[0]);
    } else {
      raw = AsnConvert.serialize(new RevokedCertificate({
        userCertificate: args[0],
        revocationDate: new Time(args[1]),
        crlEntryExtensions: args[2],
      }));
    }

    super(raw, RevokedCertificate);
  }

  protected onInit(asn: RevokedCertificate) {
    this.serialNumber = Convert.ToHex(asn.userCertificate);
    this.revocationDate = asn.revocationDate.getTime();

    this.extensions = [];
    if (asn.crlEntryExtensions) {
      this.extensions = asn.crlEntryExtensions.map((o) => {
        const extension = ExtensionFactory.create(AsnConvert.serialize(o));

        switch (extension.type) {
          case id_ce_cRLReasons:
            this.reason = AsnConvert.parse(extension.value, CRLReason).reason as unknown as X509CrlReason;
            break;
          case id_ce_invalidityDate:
            this.invalidity = AsnConvert.parse(extension.value, InvalidityDate).value;
            break;
        }

        return extension;
      }
      );
    }
  }
}
