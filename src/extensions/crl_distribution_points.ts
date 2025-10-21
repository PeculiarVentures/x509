import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { TextObject } from "../text_converter";
import { GeneralName } from "../general_name";

/**
 * Represents the CRL Distribution Points extension
 */
export class CRLDistributionPointsExtension extends Extension {
  public static override NAME = "CRL Distribution Points";

  public distributionPoints: asn1X509.DistributionPoint[];

  /**
   * Creates a new instance from DER encoded buffer
   * @param raw DER encoded buffer
   */
  public constructor(raw: BufferSource);
  /**
   * Creates a new instance
   * @param value The value of the extension
   * @param critical Indicates whether the extension is critical. Default is `false`
   */
  public constructor(value: asn1X509.DistributionPoint[], critical?: boolean);
  /**
   * Creates a new instance from an array of URLs
   * @param urls An array of URLs to be used as distribution points.
   * @param critical Indicates whether the extension is critical. Default is `false`
   */
  public constructor(urls: string[], critical?: boolean);
  public constructor(...args: any[]) {
    if (BufferSourceConverter.isBufferSource(args[0])) {
      super(args[0] as BufferSource);
    } else if (Array.isArray(args[0]) && typeof args[0][0] === "string") {
      const urls = args[0] as string[];
      const dps = urls.map((url) => {
        return new asn1X509.DistributionPoint({
          distributionPoint: new asn1X509.DistributionPointName(
            { fullName: [new asn1X509.GeneralName({ uniformResourceIdentifier: url })] },
          ),
        });
      });
      const value = new asn1X509.CRLDistributionPoints(dps);

      super(asn1X509.id_ce_cRLDistributionPoints, args[1], AsnConvert.serialize(value));
    } else {
      const value = new asn1X509.CRLDistributionPoints(args[0]);

      super(asn1X509.id_ce_cRLDistributionPoints, args[1], AsnConvert.serialize(value));
    }

    this.distributionPoints ??= [];
  }

  protected onInit(asn: asn1X509.Extension) {
    super.onInit(asn);

    const crlExt = AsnConvert.parse(asn.extnValue, asn1X509.CRLDistributionPoints);

    this.distributionPoints = crlExt;
  }

  public override toTextObject(): TextObject {
    const obj = this.toTextObjectWithoutValue();

    obj["Distribution Point"] = this.distributionPoints.map((dp) => {
      const dpObj: any = {};

      if (dp.distributionPoint) {
        dpObj[""] = dp.distributionPoint.fullName?.map((name) => new GeneralName(name).toString()).join(", ");
      }

      if (dp.reasons) {
        dpObj["Reasons"] = dp.reasons.toString();
      }

      if (dp.cRLIssuer) {
        dpObj["CRL Issuer"] = dp.cRLIssuer.map((issuer) => issuer.toString()).join(", ");
      }

      return dpObj;
    });

    return obj;
  }
}
