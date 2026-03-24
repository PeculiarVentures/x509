import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { Convert, isEqual } from "pvtsutils";
import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectKeyIdentifierExtension,
} from "./extensions";
import { cryptoProvider } from "./provider";
import { X509Certificate } from "./x509_cert";
import { X509Certificates } from "./x509_certs";

export interface X509ChainBuilderParams {
  certificates?: X509Certificate[];
}

/**
 * Represents a chain-building engine for X509Certificate certificates
 * @example
 * ```js
 * const chain = new x509.X509ChainBuilder({
 *   certificates: [
 *     new x509.X509Certificate(raw1),
 *     new x509.X509Certificate(raw2),
 *     // ...
 *     new x509.X509Certificate(rawN),
 *   ],
 * });
 *
 * const cert = x509.X509Certificate(raw);
 * const items = await chain.build(cert);
 * ```
 */
export class X509ChainBuilder {
  public certificates: X509Certificate[] = [];

  public constructor(params: X509ChainBuilderParams = {}) {
    if (params.certificates) {
      this.certificates = params.certificates;
    }
  }

  public async build(cert: X509Certificate, crypto = cryptoProvider.get()) {
    const chain = new X509Certificates(cert);
    const thumbprints = new Set<string>();
    thumbprints.add(Convert.ToHex(await cert.getThumbprint(crypto)));

    let current: X509Certificate | null = cert;
    // eslint-disable-next-line no-cond-assign
    while (current = await this.findIssuer(current, crypto)) {
      // check out circular dependency
      const thumbprint = await current.getThumbprint(crypto);
      const thumbprintHex = Convert.ToHex(thumbprint);
      if (thumbprints.has(thumbprintHex)) {
        throw new Error("Cannot build a certificate chain. Circular dependency.");
      }

      thumbprints.add(thumbprintHex);
      chain.push(current);
    }

    return chain;
  }

  private async findIssuer(cert: X509Certificate, crypto = cryptoProvider.get()) {
    if (!await cert.isSelfSigned(crypto)) {
      const akiExt = cert.getExtension<AuthorityKeyIdentifierExtension>(
        asn1X509.id_ce_authorityKeyIdentifier,
      );
      for (const item of this.certificates) {
        if (item.subject !== cert.issuer) {
          continue;
        }

        if (akiExt) {
          if (akiExt.keyId) {
            const skiExt = item.getExtension<SubjectKeyIdentifierExtension>(
              asn1X509.id_ce_subjectKeyIdentifier,
            );
            if (skiExt && skiExt.keyId !== akiExt.keyId) {
              continue;
            }
          } else if (akiExt.certId) {
            const sanExt = item.getExtension<SubjectKeyIdentifierExtension>(
              asn1X509.id_ce_subjectAltName,
            );
            if (sanExt
              && !(akiExt.certId.serialNumber === item.serialNumber && isEqual(
                AsnConvert.serialize(akiExt.certId.name),
                AsnConvert.serialize(sanExt),
              ))) {
              continue;
            }
          }
        }

        // Check Basic Constraints
        const basicConstraints = item.getExtension<BasicConstraintsExtension>(
          asn1X509.id_ce_basicConstraints,
        );
        const isV3 = item.asn.tbsCertificate.version === 2;
        if (isV3 && (!basicConstraints || !basicConstraints.ca)) {
          // RFC 5280 4.2.1.9: The basic constraints extension MUST appear as a critical extension
          // in all version 3 CA certificates.
          continue;
        }
        if (basicConstraints && !basicConstraints.ca) {
          continue;
        }

        // Check Key Usage
        const keyUsage = item.getExtension<KeyUsagesExtension>(asn1X509.id_ce_keyUsage);
        if (keyUsage && !(keyUsage.usages & KeyUsageFlags.keyCertSign)) {
          continue;
        }

        try {
          const algorithm = {
            ...item.publicKey.algorithm, ...cert.signatureAlgorithm,
          };
          const publicKey = await item.publicKey.export(algorithm, ["verify"], crypto);
          const ok = await cert.verify({
            publicKey, signatureOnly: true,
          }, crypto);
          if (!ok) {
            continue;
          }
        } catch {
          continue;
        }

        return item;
      }
    }

    return null;
  }
}
