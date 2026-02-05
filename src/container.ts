/**
 * Simple dependency injection container for edge runtime compatibility.
 * Replaces tsyringe to avoid reflect-metadata dependency which doesn't work
 * on Cloudflare Workers, Vercel Edge, Deno Deploy, etc.
 */

type Constructor<T = unknown> = new (...args: unknown[]) => T;

type Provider<T = unknown> = {
  create: () => T;
  instance?: T;
};

interface Registry {
  singletons: Map<string, Provider>;
  algorithms: Provider[];
  signatureFormatters: Provider[];
}

const registry: Registry = {
  singletons: new Map(),
  algorithms: [],
  signatureFormatters: [],
};

export const diAlgorithm = "crypto.algorithm";
export const diAlgorithmProvider = "crypto.algorithmProvider";
export const diAsnSignatureFormatter = "crypto.signatureFormatter";

const resolveProvider = <T>(provider: Provider<T>): T => {
  if (!("instance" in provider)) {
    provider.instance = provider.create();
  }
  return provider.instance as T;
};

const resolveToken = <T>(token: string): T => {
  const provider = registry.singletons.get(token);
  if (provider) {
    return resolveProvider(provider);
  }
  if (token === diAlgorithmProvider) {
    throw new Error("AlgorithmProvider not registered");
  }
  throw new Error(`Unknown token: ${token}`);
};

const createProvider = <T>(Cls: Constructor<T>, depsTokens?: string[]): Provider<T> => ({
  create: () => new Cls(...(depsTokens ? depsTokens.map(resolveToken) : [])),
});

export const container = {
  registerSingleton: <T>(token: string, Cls: Constructor<T>, depsTokens?: string[]): void => {
    const provider = createProvider(Cls, depsTokens);
    if (token === diAlgorithm) {
      registry.algorithms.push(provider);
      return;
    }
    if (token === diAsnSignatureFormatter) {
      registry.signatureFormatters.push(provider);
      return;
    }
    registry.singletons.set(token, provider);
  },

  registerInstance: <T>(token: string, instance: T): void => {
    const provider: Provider<T> = {
      create: () => instance,
      instance,
    };
    if (token === diAlgorithm) {
      registry.algorithms.push(provider);
      return;
    }
    if (token === diAsnSignatureFormatter) {
      registry.signatureFormatters.push(provider);
      return;
    }
    registry.singletons.set(token, provider);
  },

  resolve: <T>(token: string): T => {
    return resolveToken(token);
  },

  resolveAll: <T>(token: string): T[] => {
    if (token === diAlgorithm) {
      return registry.algorithms.map((provider) => resolveProvider(provider));
    }
    if (token === diAsnSignatureFormatter) {
      return registry.signatureFormatters.map((provider) => resolveProvider(provider));
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
