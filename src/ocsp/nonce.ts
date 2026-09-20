import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { BufferSourceConverter } from "pvtsutils";
import { Extension } from "../extension";
import { id_pkix_ocsp_nonce } from "@peculiar/asn1-ocsp";

export function getOcspNonce(extensions: Extension[]): ArrayBuffer | undefined {
  for (const ext of extensions) {
    if (ext.type === id_pkix_ocsp_nonce) {
      const nonce = AsnConvert.parse(ext.value, OctetString);

      return nonce.buffer;
    }
  }

  return undefined;
}

export function createOcspNonceExtension(nonce: BufferSource): Extension {
  const value = AsnConvert.serialize(new OctetString(BufferSourceConverter.toArrayBuffer(nonce)));

  return new Extension(id_pkix_ocsp_nonce, false, value);
}
