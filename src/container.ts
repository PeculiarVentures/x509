type Constructor<T = unknown> = new (...args: unknown[]) => T;

interface Provider<T = unknown> {
  create: () => T;
  instance?: T;
}

const registry = new Map<string, Provider[]>();

const resolveProvider = <T>(provider: Provider<T>): T => {
  if (!Object.prototype.hasOwnProperty.call(provider, "instance")) {
    provider.instance = provider.create();
  }

  return provider.instance as T;
};

const registerProvider = <T>(token: string, provider: Provider<T>): void => {
  const providers = registry.get(token) ?? [];
  providers.push(provider);
  registry.set(token, providers);
};

const resolveToken = <T>(token: string): T => {
  const providers = registry.get(token);

  if (!providers?.length) {
    throw new Error(`Unknown token: ${token}`);
  }

  return resolveProvider(providers[providers.length - 1] as Provider<T>);
};

const createProvider = <T>(
  Ctor: Constructor<T>,
  depsTokens: string[] = [],
): Provider<T> => {
  const dependencies = depsTokens.map((token) => resolveToken(token));
  const create = () => new Ctor(...dependencies);

  return { create };
};

export const container = {
  registerSingleton: <T>(token: string, Ctor: Constructor<T>, depsTokens: string[] = []): void => {
    registerProvider(token, createProvider(Ctor, depsTokens));
  },

  registerInstance: <T>(token: string, instance: T): void => {
    registerProvider(token, {
      create: () => instance,
      instance,
    });
  },

  resolve: <T>(token: string): T => resolveToken<T>(token),

  resolveAll: <T>(token: string): T[] => {
    const providers = registry.get(token) ?? [];
    return providers.map((provider) => resolveProvider(provider as Provider<T>));
  },
};
