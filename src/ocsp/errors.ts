import { OcspResponseStatus } from "./asn";

export class OcspError extends Error {
  public constructor(message?: string) {
    super(message);
    this.name = "OcspError";
    Object.setPrototypeOf(this, OcspError.prototype);
  }
}

export class OcspResponseStatusError extends OcspError {
  public readonly status: OcspResponseStatus;

  public constructor(status: OcspResponseStatus, message?: string) {
    super(message || `OCSP response status is '${OcspResponseStatus[status]}' (${status})`);
    this.name = "OcspResponseStatusError";
    this.status = status;
    Object.setPrototypeOf(this, OcspResponseStatusError.prototype);
  }
}

export type OcspVerifyErrorCode =
  | "signature"
  | "authorization"
  | "freshness"
  | "nonce"
  | "certId"
  | "responder";

export class OcspVerifyError extends OcspError {
  public readonly code: OcspVerifyErrorCode;

  public constructor(code: OcspVerifyErrorCode, message?: string) {
    super(message || `OCSP response verification failed: ${code}`);
    this.name = "OcspVerifyError";
    this.code = code;
    Object.setPrototypeOf(this, OcspVerifyError.prototype);
  }
}
