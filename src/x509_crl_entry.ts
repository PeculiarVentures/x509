import { AsnConvert } from "@peculiar/asn1-schema";
import { RevokedCertificate, Time } from "@peculiar/asn1-x509";
import { Extension } from "./extension";
import { ExtensionFactory } from "./extensions/extension_factory";
import { BufferSourceConverter, Convert } from "pvtsutils";
import { AsnData } from "./asn_data";

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
  * Gets crl entry extensions
  */
  public crlEntryExtensions!: Extension[];

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
    const revocationDate = asn.revocationDate.getTime();
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
