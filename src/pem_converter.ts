import { Convert } from "pvtsutils";

/**
 * Represents PEM Converter.
 */
export class PemConverter {

  public CertificateTag = "CERTIFICATE";
  public CertificateRequestTag = "CERTIFICATE REQUEST";
  public PublicKeyTag = "PUBLIC KEY";
  public PrivateKeyTag = "PRIVATE KEY";

  static isPem(data: any): data is string {
    return typeof data === "string"
      && /-{5}BEGIN [A-Z0-9 ]+-{5}([a-zA-Z0-9=+/\n\r]+)-{5}END [A-Z0-9 ]+-{5}/g.test(data);
  }

  /**
   * Decodes PEM to a list of raws
   * @param pem message in PEM format
   */
  public static decode(pem: string) {
    const pattern = /-{5}BEGIN [A-Z0-9 ]+-{5}([a-zA-Z0-9=+/\n\r]+)-{5}END [A-Z0-9 ]+-{5}/g;

    const res: ArrayBuffer[] = [];
    let matches: RegExpExecArray | null = null;
    // eslint-disable-next-line no-cond-assign
    while (matches = pattern.exec(pem)) {
      const base64 = matches[1]
        .replace(/\r/g, "")
        .replace(/\n/g, "");
      res.push(Convert.FromBase64(base64));
    }

    return res;
  }

  /**
   * Encodes a raw data to PEM format
   * @param rawData Raw data
   * @param tag PEM tag
   */
  public static encode(rawData: BufferSource, tag: string): string;
  /**
   * Encodes a list of raws to PEM format
   * @param raws A list of raws
   * @param tag PEM tag
   */
  public static encode(rawData: BufferSource[], tag: string): string;
  public static encode(rawData: BufferSource | BufferSource[], tag: string) {
    if (Array.isArray(rawData)) {
      const raws = new Array<string>();
      rawData.forEach(element => {
        raws.push(this.encodeBuffer(element, tag));
      });

      return raws.join("\n");
    } else {
      return this.encodeBuffer(rawData, tag);
    }
  }

  /**
   * Encodes a raw data to PEM format
   * @param rawData Raw data
   * @param tag PEM tag
   */
  private static encodeBuffer(rawData: BufferSource, tag: string) {
    const base64 = Convert.ToBase64(rawData);
    let sliced: string;
    let offset = 0;
    const rows = Array<string>();
    while (offset < base64.length) {
      if (base64.length - offset < 64) {
        sliced = base64.substring(offset);
      }
      else {
        sliced = base64.substring(offset, offset + 64);
        offset += 64;
      }
      if (sliced.length !== 0) {
        rows.push(sliced);
        if (sliced.length < 64) {
          break;
        }
      }
      else {
        break;
      }
    }
    const upperCaseTag = tag.toLocaleUpperCase();

    return `-----BEGIN ${upperCaseTag}-----\n${rows.join("\n")}\n-----END ${upperCaseTag}-----`;
  }
}
