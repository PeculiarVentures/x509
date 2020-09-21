/**
 * Crypto provider
 */
export class CryptoProvider extends Map<string, Crypto> {

  public static DEFAULT = "default";

  /**
   * Returns `true` if data is CryptoKeyPair
   * @param data
   */
  public static isCryptoKeyPair(data: any): data is CryptoKeyPair {
    return data && data.privateKey && data.publicKey;
  }

  public static isCryptoKey(data: any): data is CryptoKey {
    return data && data.usages && data.type && data.algorithm && data.extractable !== undefined;
  }

  /**
   * Creates a new instance
   */
  public constructor() {
    super();

    if (typeof self !== "undefined" && typeof crypto !== "undefined") { // if Browser
      // Use global crypto as default
      this.set(CryptoProvider.DEFAULT, crypto);
    }
  }

  /**
   * Returns default crypto
   * @throws Error whenever default provider not set
   */
  public get(): Crypto;
  /**
   * Returns crypto by name
   * @param key Crypto name
   * @throws Error whenever provider with specified identifier does not exist
   */
  public get(key: string): Crypto;
  public get(key = CryptoProvider.DEFAULT) {
    const crypto = super.get(key.toLowerCase());
    if (!crypto) {
      throw new Error(`Cannot get Crypto by name '${key}'`);
    }
    return crypto;
  }

  /**
   * Sets default crypto
   * @param value
   */
  public set(value: Crypto): this;
  /**
   * Sets crypto with specified identifier
   * @param key Identifier
   * @param value crypto provider
   */
  public set(key: string, value: Crypto): this;
  public set(key: string | Crypto, value?: Crypto) {
    if (typeof key === "string") {
      if (!value) {
        throw new TypeError("Argument 'value' is required");
      }
      super.set(key.toLowerCase(), value);
    } else {
      super.set(CryptoProvider.DEFAULT, key);
    }
    return this;
  }

}

/**
 * Singleton crypto provider
 */
export const cryptoProvider = new CryptoProvider();