import * as x509 from "..";
import { AuthorityInformationAccessExtension } from "../extensions";
import { OCSPResponse } from ".";

export class OCSPWorker {
  /**
   * Creates an instance of a class {@link OCSPWorker}.
   * @param certificate The certificate for which the OCSP request is to be generated
   * @param issuer The issuer's certificate
   * @param response The OCSP response
   * @param CAIssuerURL The URL of the OCSP provider
   * @param ocspURL The URL of the OCSP server
   */

  public static async create(certificate: x509.X509Certificate, issuer: x509.X509Certificate): Promise<OCSPWorker> {

    //find the extension with type  = "1.3.6.1.5.5.7.1.1"
    const authInfoAccess = certificate.extensions.find(obj => obj.type === "1.3.6.1.5.5.7.1.1") as AuthorityInformationAccessExtension;
    if(!authInfoAccess) throw new Error("No Authority Information Access extension found");

    // find OCSP URL and CA Issuers URL
    const ocspURL = authInfoAccess.getOcsp()[0];
    const caIssuers = authInfoAccess.getCaIssuers()[0];
    if(!ocspURL) throw new Error("No OCSP URL found in Authority Information Access extension");

    const request = await x509.ocsp.OCSPRequestGenerator.create({
      certificate,
      issuer,
    });

    return new OCSPWorker(certificate, issuer, request, caIssuers, ocspURL);
  }

  /*
  * The certificate for which the OCSP request is to be generated
  */
  public certificate!: x509.X509Certificate;
  /*
  * The issuer's certificate
  */
  public issuer!: x509.X509Certificate;
  /*
  * The OCSP response
  */
  public response!: OCSPResponse;
  /*
  * The URL of the OCSP provider
  */
  public CAIssuerURL!: string;
  /*
  * The URL of the OCSP server
  */
  public ocspURL!: string;
  /*
  * The OCSP request
  */
  public request!: x509.ocsp.OCSPRequest;

  constructor(certificate: x509.X509Certificate, issuer: x509.X509Certificate, request: x509.ocsp.OCSPRequest, CAIssuerURL: string, ocspURL: string) {
    this.certificate = certificate;
    this.issuer = issuer;
    this.request = request;
    this.CAIssuerURL = CAIssuerURL;
    this.ocspURL = ocspURL;
  }

  public async sendRequest(): Promise<boolean> {
    const response = await fetch(this.ocspURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/ocsp-request",
      },
      body: this.request.rawData,
    });

    if(!response.ok){
      throw new Error("OCSP request failed");
    }else{
      this.response = new OCSPResponse(await response.arrayBuffer());
      if(this.response.status !== 0){
        return false;
      }else{
        return true;
      }
    }
  }

}