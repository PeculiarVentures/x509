import * as ocsp from "@peculiar/asn1-ocsp";
import { AsnEncodedType, PemData } from "../pem_data";
import { PemConverter } from "../pem_converter";
import { BasicOCSPResponse } from "./basic_ocsp_response";
import { PublicKeyType } from "../public_key";
import { cryptoProvider } from "../provider";



export enum OCSPResponseStatus {
  successful = 0,
  malformedRequest = 1,
  internalError = 2,
  tryLater = 3,
  sigRequired = 5,
  unauthorized = 6,
}

export class OCSPResponse extends PemData<ocsp.OCSPResponse> {
  protected readonly tag;

  /**
   * OCSP response status
   */
  public status!: OCSPResponseStatus;

  /**
   * OCSP response
   * If the OCSP response status is not 0, then the value is null
   */
  public basicResponse!: BasicOCSPResponse | null;

  protected onInit(asn: ocsp.OCSPResponse): void {
    this.status = asn.responseStatus;
    if (!this.status) {
      if (asn.responseBytes) {
        this.basicResponse = new BasicOCSPResponse(asn.responseBytes.response.buffer);
      }
    } else {
      this.basicResponse = null;
    }
  }

  constructor(raw: AsnEncodedType);
  constructor(tbsRequest: ocsp.OCSPResponse);
  public constructor(param: AsnEncodedType | ocsp.OCSPResponse) {
    if (PemData.isAsnEncoded(param)) {
      super(param, ocsp.OCSPResponse);
    } else {
      super(param);
    }

    this.tag = PemConverter.OCSPResponseTag;
  }
  public async verify(signer: PublicKeyType, crypto = cryptoProvider.get()): Promise<boolean> {
    if (this.basicResponse) {
      return this.basicResponse.verify(signer, crypto);
    }

    return false;
  }
}