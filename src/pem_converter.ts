import * as bytes from "@peculiar/utils/bytes";
import { base64 } from "@peculiar/utils/encoding";

const rPaddingTag = "-{5}";
const rEolChars = "\\n";
const rNameTag = `[^${rEolChars}]+`;
const rBeginTag = `${rPaddingTag}BEGIN (${rNameTag}(?=${rPaddingTag}))${rPaddingTag}`;
const rEndTag = `${rPaddingTag}END \\1${rPaddingTag}`;
const rEolGroup = "\\n";
const rHeaderKey = `[^:${rEolChars}]+`;
const rHeaderValue = `(?:[^${rEolChars}]+${rEolGroup}(?: +[^${rEolChars}]+${rEolGroup})*)`;
const rBase64Chars = "[a-zA-Z0-9=+/]+";
const rBase64 = `(?:${rBase64Chars}${rEolGroup})+`;
const rPem = `${rBeginTag}${rEolGroup}(?:((?:${rHeaderKey}: ${rHeaderValue})+))?${rEolGroup}?(${rBase64})${rEndTag}`;
const rEolPattern = new RegExp(`[${rEolChars}]+`, "g");

export interface PemHeader {
  key: string;
  value: string;
}

/**
 * Represents PEM structure
 */
export interface PemStruct {
  /**
   * Type
   */
  type: string;
  /**
   * Headers
   */
  headers: PemHeader[];

  /**
   * Decoded message data
   */
  rawData: ArrayBuffer;
}

type AtLeast<T, K extends keyof T> = Partial<T> & Pick<T, K>;

export type PemStructEncodeParams = AtLeast<PemStruct, "type" | "rawData">;

/**
 * Represents PEM Converter.
 */
export class PemConverter {
  public static CertificateTag = "CERTIFICATE";
  public static CrlTag = "CRL";
  public static CertificateRequestTag = "CERTIFICATE REQUEST";
  public static PublicKeyTag = "PUBLIC KEY";
  public static PrivateKeyTag = "PRIVATE KEY";

  public static isPem(data: any): data is string {
    return typeof data === "string"
      && new RegExp(rPem, "g").test(data.replace(/\r/g, ""));
  }

  public static decodeWithHeaders(pem: string): PemStruct[] {
    pem = pem.replace(/\r/g, ""); // CRLF -> LF
    const pattern = new RegExp(rPem, "g");

    const res: PemStruct[] = [];

    let matches: RegExpExecArray | null = null;
    // eslint-disable-next-line no-cond-assign
    while (matches = pattern.exec(pem)) {
      // prepare pem encoded message
      const base64String = matches[3]
        .replace(rEolPattern, "");

      const pemStruct: PemStruct = {
        type: matches[1],
        headers: [],
        rawData: bytes.toArrayBuffer(base64.decode(base64String)),
      };

      // read headers
      const headersString = matches[2];
      if (headersString) {
        const headers = headersString.split(new RegExp(rEolGroup, "g"));
        let lastHeader: PemHeader | null = null;
        for (const header of headers) {
          const [key, value] = header.split(/:(.*)/);
          if (value === undefined) {
            // value
            if (!lastHeader) {
              throw new Error("Cannot parse PEM string. Incorrect header value");
            }
            lastHeader.value += key.trim();
          } else {
            // key and value
            if (lastHeader) {
              pemStruct.headers.push(lastHeader);
            }
            lastHeader = {
              key, value: value.trim(),
            };
          }
        }
        // add last header
        if (lastHeader) {
          pemStruct.headers.push(lastHeader);
        }
      }

      res.push(pemStruct);
    }

    return res;
  }

  /**
   * Decodes PEM to a list of raws
   * @param pem message in PEM format
   */
  public static decode(pem: string): ArrayBuffer[] {
    const blocks = this.decodeWithHeaders(pem);

    return blocks.map((o) => o.rawData);
  }

  /**
   * Decodes PEM and returns first item from the list
   * @param pem message in PEM format
   * @throw Throws RangeError if list of decoded items is empty
   */
  public static decodeFirst(pem: string): ArrayBuffer {
    const items = this.decode(pem);
    if (!items.length) {
      throw new RangeError("PEM string doesn't contain any objects");
    }

    return items[0];
  }

  /**
   * Encodes a list of PemStruct in PEM format
   * @param structs A list of PemStruct
   * @param tag PEM tag
   */
  public static encode(structs: PemStructEncodeParams[]): string;
  /**
   * Encodes a raw data in PEM format
   * @param rawData Raw data
   * @param tag PEM tag
   */
  public static encode(rawData: bytes.BufferSourceLike, tag: string): string;
  /**
   * Encodes a list of raws in PEM format
   * @param raws A list of raws
   * @param tag PEM tag
   */
  public static encode(rawData: bytes.BufferSourceLike[], tag: string): string;
  public static encode(
    rawData: bytes.BufferSourceLike | bytes.BufferSourceLike[] | PemStructEncodeParams[],
    tag?: string,
  ) {
    if (Array.isArray(rawData)) {
      const raws = new Array<string>();
      if (tag) {
        // encode bytes.BufferSourceLike[]
        rawData.forEach((element) => {
          if (!bytes.isBufferSource(element)) {
            throw new TypeError("Cannot encode array of bytes.BufferSourceLike in PEM format. Not all items of the array are bytes.BufferSourceLike");
          }
          raws.push(this.encodeStruct({
            type: tag,
            rawData: bytes.toArrayBuffer(element),
          }));
        });
      } else {
        // encode PemStruct[]
        rawData.forEach((element) => {
          if (!("type" in element)) {
            throw new TypeError("Cannot encode array of PemStruct in PEM format. Not all items of the array are PemStrut");
          }
          raws.push(this.encodeStruct(element));
        });
      }

      return raws.join("\n");
    } else {
      if (!tag) {
        throw new Error("Required argument 'tag' is missed");
      }

      return this.encodeStruct({
        type: tag,
        rawData: bytes.toArrayBuffer(rawData),
      });
    }
  }

  /**
   * Encodes PEMStruct in PEM block
   * @param pem PEM structure for encoding
   * @returns Returns PEM encoded block
   */
  private static encodeStruct(pem: PemStructEncodeParams): string {
    const upperCaseType = pem.type.toLocaleUpperCase();

    const res: string[] = [];
    res.push(`-----BEGIN ${upperCaseType}-----`);

    if (pem.headers?.length) {
      for (const header of pem.headers) {
        res.push(`${header.key}: ${header.value}`);
      }

      res.push(""); // blank line
    }

    const base64String = base64.encode(pem.rawData);
    for (let i = 0; i < base64String.length; i += 64) {
      res.push(base64String.substring(i, i + 64));
    }

    res.push(`-----END ${upperCaseType}-----`);

    return res.join("\n");
  }
}
