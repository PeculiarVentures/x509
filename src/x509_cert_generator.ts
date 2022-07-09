import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { BufferSource, BufferSourceConverter, Convert } from "pvtsutils";
import { container } from "tsyringe";
import { cryptoProvider } from "./provider";
import { AlgorithmProvider, diAlgorithmProvider } from "./algorithm";
import { Extension } from "./extension";
import { JsonName, Name } from "./name";
import { HashedAlgorithm } from "./types";
import { X509Certificate } from "./x509_cert";
import { diAsnSignatureFormatter, IAsnSignatureFormatter } from "./asn_signature_formatter";
import { PublicKey, PublicKeyType } from "./public_key";

export type X509CertificateCreateParamsName = string | JsonName | Name;

/**
 * Base arguments for certificate creation
 */
export interface X509CertificateCreateParamsBase {
  /**
   * Hexadecimal serial number
   */
  serialNumber: string;
  /**
   * Date before which certificate can't be used
   */
  notBefore: Date;
  /**
   * Date after which certificate can't be used
   */
  notAfter: Date;
  /**
   * List of extensions
   */
  extensions?: Extension[];
  /**
   * Signing algorithm
   */
  signingAlgorithm: Algorithm | EcdsaParams;
  /**
   * Signature for manually initialized certificates
   */
  signature?: BufferSource;
}

/**
 * Parameters for X509 Certificate generation
 */
export interface X509CertificateCreateParams extends X509CertificateCreateParamsBase {
  subject?: X509CertificateCreateParamsName;
  issuer?: X509CertificateCreateParamsName;
  publicKey: PublicKeyType;
  signingKey: CryptoKey;
}

/**
 * Parameters for self-signed X509 Certificate generation
 */
export interface X509CertificateCreateSelfSignedParams extends X509CertificateCreateParamsBase {
  name?: X509CertificateCreateParamsName;
  keys: CryptoKeyPair;
}

/**
 * Generator of X509 certificates
 */
export class X509CertificateGenerator {

  /**
   * Creates a self-signed certificate
   * @param params Parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public static async createSelfSigned(params: X509CertificateCreateSelfSignedParams, crypto = cryptoProvider.get()) {
    if (!params.keys.privateKey) {
      throw new Error("Bad field 'keys' in 'params' argument. 'privateKey' is empty");
    }
    if (!params.keys.publicKey) {
      throw new Error("Bad field 'keys' in 'params' argument. 'privateKey' is empty");
    }

    return this.create({
      serialNumber: params.serialNumber,
      subject: params.name,
      issuer: params.name,
      notBefore: params.notBefore,
      notAfter: params.notAfter,
      publicKey: params.keys.publicKey,
      signingKey: params.keys.privateKey,
      signingAlgorithm: params.signingAlgorithm,
      extensions: params.extensions,
    }, crypto);
  }

  /**
   * Creates a certificate signed by private key
   * @param params Parameters
   * @param crypto Crypto provider. Default is from CryptoProvider
   */
  public static async create(params: X509CertificateCreateParams, crypto = cryptoProvider.get()) {
    let spki: BufferSource;
    if (params.publicKey instanceof PublicKey) {
      spki = params.publicKey.rawData;
    } else if ("publicKey" in params.publicKey) {
      spki = params.publicKey.publicKey.rawData;
    } else if (BufferSourceConverter.isBufferSource(params.publicKey)) {
      spki = params.publicKey;
    } else {
      spki = await crypto.subtle.exportKey("spki", params.publicKey);
    }

    const asnX509 = new asn1X509.Certificate({
      tbsCertificate: new asn1X509.TBSCertificate({
        version: asn1X509.Version.v3,
        serialNumber: Convert.FromHex(params.serialNumber),
        validity: new asn1X509.Validity({
          notBefore: params.notBefore,
          notAfter: params.notAfter,
        }),
        extensions: new asn1X509.Extensions(params.extensions?.map(o => AsnConvert.parse(o.rawData, asn1X509.Extension)) || []),
        subjectPublicKeyInfo: AsnConvert.parse(spki, asn1X509.SubjectPublicKeyInfo),
      }),
    });
    if (params.subject) {
      const name = params.subject instanceof Name
        ? params.subject
        : new Name(params.subject);
      asnX509.tbsCertificate.subject = AsnConvert.parse(name.toArrayBuffer(), asn1X509.Name);
    }
    if (params.issuer) {
      const name = params.issuer instanceof Name
        ? params.issuer
        : new Name(params.issuer);
      asnX509.tbsCertificate.issuer = AsnConvert.parse(name.toArrayBuffer(), asn1X509.Name);
    }

    // Set signing algorithm
    const signingAlgorithm = { ...params.signingAlgorithm, ...params.signingKey.algorithm } as HashedAlgorithm;
    const algProv = container.resolve<AlgorithmProvider>(diAlgorithmProvider);
    asnX509.tbsCertificate.signature = asnX509.signatureAlgorithm = algProv.toAsnAlgorithm(signingAlgorithm);

    // Sign
    const tbs = AsnConvert.serialize(asnX509.tbsCertificate);
    const signature = params.signature || await crypto.subtle.sign(signingAlgorithm, params.signingKey, tbs);

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

    asnX509.signatureValue = asnSignature;

    return new X509Certificate(AsnConvert.serialize(asnX509));
  }

}