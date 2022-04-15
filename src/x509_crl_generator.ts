import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { container } from "tsyringe";
import { cryptoProvider } from "./provider";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";
import { Extension } from "./extension";
import { Name } from "./name";
import { HashedAlgorithm } from "./types";
import { diAsnSignatureFormatter, IAsnSignatureFormatter } from "./asn_signature_formatter";
import { X509CrlEntry, X509CRLReason } from "./x509_crl_entry";
import { CRLReason, id_ce_cRLReasons, id_ce_invalidityDate, InvalidityDate, RevokedCertificate, Time } from "@peculiar/asn1-x509";
import { X509Crl } from "./x509_crl";
import { X509CertificateCreateParamsName } from "./x509_cert_generator";
import { PemData } from "./pem_data";
import { BufferSourceConverter, Convert } from "pvtsutils";

interface X509CrlEntryParamsBase {
  /**
   * Hexadecimal serial number
   */
  serialNumber: string;
  revocationDate: Date;
}

interface X509CrlEntryParams extends X509CrlEntryParamsBase {
  reason?: X509CRLReason;
  invalidity?: Date;
  issuer?: X509CertificateCreateParamsName;
}

export type X509CrlEntryParamsForCreate = X509CrlEntry[] | X509CrlEntryParams[];

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
  entries?: X509CrlEntryParamsForCreate;
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
        version: asn1X509.Version.v3,
        issuer: AsnConvert.parse(name.toArrayBuffer(), asn1X509.Name),
        thisUpdate: params.thisUpdate ? new Time(params.thisUpdate) : new Time(new Date()),
      }),
    });

    if (params.nextUpdate) {
      asnX509Crl.tbsCertList.nextUpdate = new Time(params.nextUpdate);
    }

    if (params.extensions && params.extensions.length) {
      asnX509Crl.tbsCertList.crlExtensions = new asn1X509.Extensions(params.extensions.map(o => AsnConvert.parse(o.rawData, asn1X509.Extension)) || []);
    }

    if (params.entries) {
      asnX509Crl.tbsCertList.revokedCertificates = [];
      for (const entry of params.entries || []) {
        const revokedCert = new RevokedCertificate({
          userCertificate: PemData.toArrayBuffer(entry.serialNumber),
          revocationDate: new Time(entry.revocationDate),
        });
        if ("extensions" in entry && entry.extensions?.length) {
          revokedCert.crlEntryExtensions = entry.extensions.map(o => AsnConvert.parse(o.rawData, asn1X509.Extension));
        }
        asnX509Crl.tbsCertList.revokedCertificates.push(revokedCert);
      }
    }

    // Set signing algorithm
    const signingAlgorithm = { ...params.signingAlgorithm, ...params.signingKey.algorithm } as HashedAlgorithm;
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    asnX509Crl.tbsCertList.signature = asnX509Crl.signatureAlgorithm = algProv.toAsnAlgorithm(signingAlgorithm);

    // Sign
    const tbs = AsnConvert.serialize(asnX509Crl.tbsCertList);
    const signature = await crypto.subtle.sign(signingAlgorithm, params.signingKey, tbs);

    // Convert WebCrypto signature to ASN.1 format
    const signatureFormatters = container.resolveAll<IAsnSignatureFormatter>(diAsnSignatureFormatter).reverse();
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
