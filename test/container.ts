import { describe, it, expect } from "vitest";
import { container } from "../src";

describe("container", () => {
  it("injects constructor deps via token list", () => {
    const depToken = "test.dep";
    const fooToken = "test.foo";

    class Dep {
      public value = "ok";
    }

    class Foo {
      public dep: Dep;

      constructor(dep: Dep) {
        this.dep = dep;
      }
    }

    container.registerSingleton(depToken, Dep);
    container.registerSingleton(fooToken, Foo, [depToken]);

    const foo = container.resolve<Foo>(fooToken);
    expect(foo.dep).toBeInstanceOf(Dep);
    expect(foo.dep.value).toBe("ok");
  });

  it("injects instance registrations", () => {
    const cfgToken = "test.cfg";
    const fooToken = "test.foo.instance";
    const cfg = { name: "cfg" };

    class Foo {
      public cfg: { name: string };

      constructor(config: { name: string }) {
        this.cfg = config;
      }
    }

    container.registerInstance(cfgToken, cfg);
    container.registerSingleton(fooToken, Foo, [cfgToken]);

    const foo = container.resolve<Foo>(fooToken);
    expect(foo.cfg).toBe(cfg);
  });

  it("throws for unknown tokens", () => {
    expect(() => container.resolve("test.unknown")).toThrow(/Unknown token/);
  });
});
