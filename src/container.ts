/**
 * Simple dependency injection container for edge runtime compatibility.
 * Replaces tsyringe to avoid reflect-metadata dependency which doesn't work
 * on Cloudflare Workers, Vercel Edge, Deno Deploy, etc.
 */

type Constructor<T = unknown> = new (...args: unknown[]) => T;

interface Registry {
  algorithms: unknown[];
  algorithmProvider: unknown | null;
  signatureFormatters: unknown[];
}

const registry: Registry = {
  algorithms: [],
  algorithmProvider: null,
  signatureFormatters: [],
};

export const diAlgorithm = "crypto.algorithm";
export const diAlgorithmProvider = "crypto.algorithmProvider";
export const diAsnSignatureFormatter = "crypto.signatureFormatter";

export const container = {
  registerSingleton: <T>(token: string, Cls: Constructor<T>): void => {
    if (token === diAlgorithmProvider) {
      registry.algorithmProvider = new Cls();
    } else if (token === diAlgorithm) {
      registry.algorithms.push(new Cls());
    } else if (token === diAsnSignatureFormatter) {
      registry.signatureFormatters.push(new Cls());
    }
  },

  resolve: <T>(token: string): T => {
    if (token === diAlgorithmProvider) {
      if (!registry.algorithmProvider) {
        throw new Error("AlgorithmProvider not registered");
      }
      return registry.algorithmProvider as T;
    }
    throw new Error(`Unknown token: ${token}`);
  },

  resolveAll: <T>(token: string): T[] => {
    if (token === diAlgorithm) {
      return registry.algorithms as T[];
    }
    if (token === diAsnSignatureFormatter) {
      return registry.signatureFormatters as T[];
    }
    return [];
  },
};

/**
 * No-op decorator for backwards compatibility.
 * Previously used with tsyringe's @injectable() decorator.
 */
export function injectable(): ClassDecorator {
  return (target) => target;
}
