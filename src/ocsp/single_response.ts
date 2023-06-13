import * as ocsp from "@peculiar/asn1-ocsp";
import { AsnConvert } from "@peculiar/asn1-schema";
import { AsnData } from "../asn_data";
import { IExtensionable } from "../types";
import { CertificateID } from "./cert_id";
import { Extension } from "../extension";
import { AsnEncodedType, PemData } from "../pem_data";
import { ExtensionFactory } from "../extensions/extension_factory";

export class SingleResponse extends AsnData<ocsp.SingleResponse> implements IExtensionable {

  /**
   * The ID of the certificate for which the status is being returned
   */
  public certificateID!: CertificateID;

  /**
   * Certificate status
   */
  public status!: boolean;

  public thisUpdate!: Date;

  public nextUpdate?: Date;

  public extensions!: Extension[];

  protected onInit(asn: ocsp.SingleResponse): void {
    this.certificateID = new CertificateID(asn.certID);
    this.status = asn.certStatus.good ? true : false;
    this.thisUpdate = asn.thisUpdate;
    if (asn.nextUpdate) {
      this.nextUpdate = asn.nextUpdate;
    }
    this.extensions = [];
    if (asn.singleExtensions) {
      this.extensions = asn.singleExtensions.map((o) =>
        ExtensionFactory.create(AsnConvert.serialize(o))
      );
    }
  }

  constructor(raw: AsnEncodedType);
  constructor(asn: ocsp.SingleResponse);
  public constructor(param: AsnEncodedType | ocsp.SingleResponse) {
    if (PemData.isAsnEncoded(param)) {
      super(PemData.toArrayBuffer(param), ocsp.SingleResponse);
    } else {
      super(param);
    }
  }

  public getExtension<T extends Extension>(type: new () => T): T | null;
  public getExtension<T extends Extension>(type: string): T | null;
  public getExtension<T extends Extension>(type: { new(): T; } | string): T | null {
    for (const ext of this.extensions) {
      if (typeof type === "string") {
        if (ext.type === type) {
          return ext as T;
        }
      } else {
        if (ext instanceof type) {
          return ext;
        }
      }
    }

    return null;
  }

  public getExtensions<T extends Extension>(type: new () => T): T[];
  public getExtensions<T extends Extension>(type: string): T[];
  public getExtensions<T extends Extension>(type: string | { new(raw: BufferSource): T; }): T[] {
    return this.extensions.filter(o => {
      if (typeof type === "string") {
        return o.type === type;
      } else {
        return o instanceof type;
      }
    }) as T[];
  }
}