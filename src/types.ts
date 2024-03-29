import { Extension } from "./extension";

export interface HashedAlgorithm extends Algorithm {
  hash: Algorithm;
}

export interface IExtensionable {
  extensions: Extension[];

  /**
   * Returns an extension of specified type
   * @param type Extension identifier
   * @returns Extension or null
   */
  getExtension<T extends Extension>(type: string): T | null;

  /**
   * Returns an extension of specified type
   * @param type Extension type
   * @returns Extension or null
   */
  getExtension<T extends Extension>(type: new () => T): T | null;

  /**
   * Returns a list of extensions of specified type
   * @param type Extension identifier
   */
  getExtensions<T extends Extension>(type: string): T[];

  /**
   * Returns a list of extensions of specified type
   * @param type Extension type
   */
  getExtensions<T extends Extension>(type: new () => T): T[];
}