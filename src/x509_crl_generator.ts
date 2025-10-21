import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { container } from "tsyringe";
import {
  CRLReasons, RevokedCertificate, Time,
} from "@peculiar/asn1-x509";
import { isEqual } from "pvtsutils";
import { cryptoProvider } from "./provider";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";
import { Extension } from "./extension";
import { Name } from "./name";
import { HashedAlgorithm } from "./types";
import { diAsnSignatureFormatter, IAsnSignatureFormatter } from "./asn_signature_formatter";
import { X509CrlEntry, X509CrlReason } from "./x509_crl_entry";
import { X509Crl } from "./x509_crl";
import { X509CertificateCreateParamsName } from "./x509_cert_generator";
import { PemData } from "./pem_data";

export interface X509CrlEntryParams {
  /**
   * Hexadecimal serial number
   */
  serialNumber: string;
  revocationDate?: Date;
  reason?: X509CrlReason;
  invalidity?: Date;
  issuer?: X509CertificateCreateParamsName;
  extensions?: Extension[];
}

/**
 * Base arguments for crl creation
 */
export interface X509CrlCreateParamsBase {
  issuer: X509CertificateCreateParamsName;
  thisUpdate?: Date;
  /**
   * Signing algorithm
   */
  signingAlgorithm: Algorithm | EcdsaParams;
}

/**
 * Parameters for X509 CRL generation
 */
export interface X509CrlCreateParams extends X509CrlCreateParamsBase {
  nextUpdate?: Date;
  extensions?: Extension[];
  entries?: X509CrlEntryParams[];
  signingKey: CryptoKey;
}

/**
 * Generator of X509 crl
 */
export class X509CrlGenerator {
  /**
   * Creates a crl signed by private key
   * @param params Parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public static async create(params: X509CrlCreateParams, crypto = cryptoProvider.get()) {
    const name = params.issuer instanceof Name
      ? params.issuer
      : new Name(params.issuer);
    const asnX509Crl = new asn1X509.CertificateList({
      tbsCertList: new asn1X509.TBSCertList({
        version: asn1X509.Version.v2,
        issuer: AsnConvert.parse(name.toArrayBuffer(), asn1X509.Name),
        thisUpdate: new Time(params.thisUpdate || new Date()),
      }),
    });

    if (params.nextUpdate) {
      asnX509Crl.tbsCertList.nextUpdate = new Time(params.nextUpdate);
    }

    if (params.extensions && params.extensions.length) {
      asnX509Crl.tbsCertList.crlExtensions = new asn1X509.Extensions(
        params.extensions.map((o) => AsnConvert.parse(o.rawData, asn1X509.Extension)) || [],
      );
    }

    if (params.entries && params.entries.length) {
      asnX509Crl.tbsCertList.revokedCertificates = [];
      for (const entry of params.entries) {
        const userCertificate = PemData.toArrayBuffer(entry.serialNumber);
        const index = asnX509Crl.tbsCertList.revokedCertificates
          .findIndex((cert) => isEqual(cert.userCertificate, userCertificate));
        if (index > -1) {
          throw new Error(`Certificate serial number ${entry.serialNumber} already exists in tbsCertList`);
        }

        const revokedCert = new RevokedCertificate({
          userCertificate: userCertificate,
          revocationDate: new Time(entry.revocationDate || new Date()),
        });

        if ("extensions" in entry && entry.extensions?.length) {
          revokedCert.crlEntryExtensions = entry.extensions.map((o) => (
            AsnConvert.parse(o.rawData, asn1X509.Extension)
          ));
        } else {
          revokedCert.crlEntryExtensions = [];
        }

        if (!(entry instanceof X509CrlEntry)) {
          if (entry.reason) {
            revokedCert.crlEntryExtensions.push(new asn1X509.Extension({
              extnID: asn1X509.id_ce_cRLReasons,
              critical: false,
              extnValue: new OctetString(AsnConvert.serialize(
                new asn1X509.CRLReason(entry.reason as unknown as CRLReasons),
              )),
            }));
          }

          if (entry.invalidity) {
            revokedCert.crlEntryExtensions.push(new asn1X509.Extension({
              extnID: asn1X509.id_ce_invalidityDate,
              critical: false,
              extnValue: new OctetString(AsnConvert.serialize(
                new asn1X509.InvalidityDate(entry.invalidity),
              )),
            }));
          }

          if (entry.issuer) {
            const name = params.issuer instanceof Name
              ? params.issuer
              : new Name(params.issuer);

            revokedCert.crlEntryExtensions.push(new asn1X509.Extension({
              extnID: asn1X509.id_ce_certificateIssuer,
              critical: false,
              extnValue: new OctetString(AsnConvert.serialize(
                AsnConvert.parse(name.toArrayBuffer(), asn1X509.Name),
              )),
            }));
          }
        }

        asnX509Crl.tbsCertList.revokedCertificates.push(revokedCert);
      }
    }

    // Set signing algorithm
    const signingAlgorithm = {
      ...params.signingAlgorithm, ...params.signingKey.algorithm,
    } as HashedAlgorithm;
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    asnX509Crl.tbsCertList.signature = asnX509Crl.signatureAlgorithm = algProv
      .toAsnAlgorithm(signingAlgorithm);

    // Sign
    const tbs = AsnConvert.serialize(asnX509Crl.tbsCertList);
    const signature = await crypto.subtle.sign(signingAlgorithm, params.signingKey, tbs);

    // Convert WebCrypto signature to ASN.1 format
    const signatureFormatters = container
      .resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter)
      .reverse();
    let asnSignature: ArrayBuffer | null = null;
    for (const signatureFormatter of signatureFormatters) {
      asnSignature = signatureFormatter.toAsnSignature(signingAlgorithm, signature);
      if (asnSignature) {
        break;
      }
    }
    if (!asnSignature) {
      throw Error("Cannot convert ASN.1 signature value to WebCrypto format");
    }

    asnX509Crl.signature = asnSignature;

    return new X509Crl(AsnConvert.serialize(asnX509Crl));
  }
}
