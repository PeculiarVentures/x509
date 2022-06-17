export type MapForEachCallback = (value: Crypto, key: string, map: Map<string, Crypto>) => void;

/**
 * Crypto provider
 */
export class CryptoProvider implements Map<string, Crypto> {

  public static DEFAULT = "default";

  private items = new Map<string, Crypto>();

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
    if (typeof self !== "undefined" && typeof crypto !== "undefined") { // if Browser
      // Use global crypto as default
      this.set(CryptoProvider.DEFAULT, crypto);
    }
  }
  clear(): void {
    this.items.clear();
  }

  delete(key: string): boolean {
    return this.items.delete(key);
  }

  forEach(callbackfn: MapForEachCallback, thisArg?: any): void {
    return this.items.forEach(callbackfn, thisArg);
  }

  has(key: string): boolean {
    return this.items.has(key);
  }

  get size(): number {
    return this.items.size;
  }

  entries(): IterableIterator<[string, Crypto]> {
    return this.items.entries();
  }

  keys(): IterableIterator<string> {
    return this.items.keys();
  }
  values(): IterableIterator<Crypto> {
    return this.items.values();
  }
  [Symbol.iterator](): IterableIterator<[string, Crypto]> {
    return this.items[Symbol.iterator]();
  }
  [Symbol.toStringTag] = "CryptoProvider";

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
    const crypto = this.items.get(key.toLowerCase());
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
      this.items.set(key.toLowerCase(), value);
    } else {
      this.items.set(CryptoProvider.DEFAULT, key);
    }

    return this;
  }

}

/**
 * Singleton crypto provider
 */
export const cryptoProvider = new CryptoProvider();