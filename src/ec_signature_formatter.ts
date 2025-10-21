import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnConvert } from "@peculiar/asn1-schema";
import { BufferSourceConverter, combine } from "pvtsutils";
import { IAsnSignatureFormatter } from "./asn_signature_formatter";

export class AsnEcSignatureFormatter implements IAsnSignatureFormatter {
  public static namedCurveSize = new Map<string, number>();
  public static defaultNamedCurveSize = 32;

  private addPadding(pointSize: number, data: BufferSource): ArrayBuffer {
    const bytes = BufferSourceConverter.toUint8Array(data);
    const res = new Uint8Array(pointSize);

    res.set(bytes, pointSize - bytes.length);

    return res.buffer as ArrayBuffer;
  }

  private removePadding(data: BufferSource, positive = false): ArrayBuffer {
    let bytes = BufferSourceConverter.toUint8Array(data);

    for (let i = 0; i < bytes.length; i++) {
      if (!bytes[i]) {
        continue;
      }

      bytes = bytes.slice(i);

      break;
    }

    if (positive && bytes[0] > 127) {
      // Add 0 padding to make ASN.1 positive Integer value
      const result = new Uint8Array(bytes.length + 1);

      result.set(bytes, 1);

      return result.buffer;
    }

    return bytes.buffer as ArrayBuffer;
  }

  public toAsnSignature(algorithm: Algorithm, signature: BufferSource): ArrayBuffer | null {
    if (algorithm.name === "ECDSA") {
      const namedCurve = (algorithm as EcKeyAlgorithm).namedCurve;

      const pointSize = AsnEcSignatureFormatter.namedCurveSize.get(namedCurve)
        || AsnEcSignatureFormatter.defaultNamedCurveSize;
      const ecSignature = new ECDSASigValue();
      const uint8Signature = BufferSourceConverter.toUint8Array(signature);

      ecSignature.r = this.removePadding(uint8Signature.slice(0, pointSize), true);
      ecSignature.s = this.removePadding(
        uint8Signature.slice(pointSize, pointSize + pointSize),
        true,
      );

      return AsnConvert.serialize(ecSignature);
    }

    return null;
  }

  public toWebSignature(algorithm: Algorithm, signature: BufferSource): ArrayBuffer | null {
    if (algorithm.name === "ECDSA") {
      const ecSigValue = AsnConvert.parse(signature, ECDSASigValue);
      const namedCurve = (algorithm as EcKeyAlgorithm).namedCurve;

      const pointSize = AsnEcSignatureFormatter.namedCurveSize.get(namedCurve)
        || AsnEcSignatureFormatter.defaultNamedCurveSize;
      const r = this.addPadding(pointSize, this.removePadding(ecSigValue.r));
      const s = this.addPadding(pointSize, this.removePadding(ecSigValue.s));

      return combine(r, s) as ArrayBuffer;
    }

    return null;
  }
}
