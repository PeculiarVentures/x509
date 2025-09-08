import { AsnConvert } from "@peculiar/asn1-schema";
import { CRLReason, id_ce_cRLReasons, id_ce_invalidityDate, InvalidityDate, RevokedCertificate, Time } from "@peculiar/asn1-x509";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { Extension } from "./extension";
import { ExtensionFactory } from "./extensions/extension_factory";
import { AsnData } from "./asn_data";
import { generateCertificateSerialNumber } from "./utils";

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
   * Serial number
   */
  #serialNumber?: string;

  /**
   * Revocation date
   */
  #revocationDate?: Date;

  /**
   * Reason code
   */
  #reason?: X509CrlReason;

  /**
   * Invalidity date
   */
  #invalidity?: Date;

  /**
   * CRL entry extensions
   */
  #extensions?: Extension[];

  /**
   * Gets a hexadecimal string of the serial number, the userCertificate
   */
  public get serialNumber(): string {
    if (!this.#serialNumber) {
      this.#serialNumber = Convert.ToHex(this.asn.userCertificate);
    }

    return this.#serialNumber;
  }

  /**
   * Gets the revocation date
   */
  public get revocationDate(): Date {
    if (!this.#revocationDate) {
      this.#revocationDate = this.asn.revocationDate.getTime();
    }

    return this.#revocationDate;
  }

  /**
   * Gets the reason code
   */
  public get reason(): X509CrlReason | undefined {
    if (this.#reason === undefined) {
      // Trigger extensions loading to set reason
      void this.extensions;
    }

    return this.#reason;
  }

  /**
   * Gets the invalidity Date
   * The invalidity date is a non-critical CRL entry extension that
   * provides the date on which it is known or suspected that the private
   * key was compromised or that the certificate otherwise became invalid.
   */
  public get invalidity(): Date | undefined {
    if (this.#invalidity === undefined) {
      // Trigger extensions loading to set invalidity
      void this.extensions;
    }

    return this.#invalidity;
  }

  /**
   * Gets crl entry extensions
   */
  public get extensions(): Extension[] {
    if (!this.#extensions) {
      this.#extensions = [];
      if (this.asn.crlEntryExtensions) {
        this.#extensions = this.asn.crlEntryExtensions.map((o) => {
          const extension = ExtensionFactory.create(AsnConvert.serialize(o));

          switch (extension.type) {
            case id_ce_cRLReasons:
              if (this.#reason === undefined) {
                this.#reason = AsnConvert.parse(extension.value, CRLReason).reason as unknown as X509CrlReason;
              }
              break;
            case id_ce_invalidityDate:
              if (this.#invalidity === undefined) {
                this.#invalidity = AsnConvert.parse(extension.value, InvalidityDate).value;
              }
              break;
          }

          return extension;
        });
      }
    }

    return this.#extensions;
  }

  /**
   * Creates a new instance from DER encoded Buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance from ASN.1 object
   * @param asn ASN.1 object
   */
  public constructor(asn: RevokedCertificate);
  /**
   * Creates a new instance
   * @param serialNumber Serial number of certificate
   * @param revocationDate Revocation date
   * @param extensions List of crl extensions
   */
  public constructor(serialNumber: string, revocationDate: Date, extensions: Extension[]);
  public constructor(...args: any[]) {
    let raw: ArrayBuffer | RevokedCertificate | undefined;
    if (BufferSourceConverter.isBufferSource(args[0])) {
      raw = BufferSourceConverter.toArrayBuffer(args[0]);
    } else if (typeof args[0] === "string") {
      raw = AsnConvert.serialize(new RevokedCertificate({
        userCertificate: generateCertificateSerialNumber(args[0]),
        revocationDate: new Time(args[1]),
        crlEntryExtensions: args[2],
      }));
    } else if (args[0] instanceof RevokedCertificate) {
      raw = args[0];
    }

    if (!raw) {
      throw new TypeError("Cannot create X509CrlEntry instance. Wrong constructor arguments.");
    }

    // @ts-expect-error : next line is ok
    super(raw, RevokedCertificate);
  }

  protected onInit(_asn: RevokedCertificate) {
    // Initialization is now lazy
  }
}
