import { describe, it, expect, beforeAll, afterEach, vi } from "vitest";
import * as x509 from "./index";

function corruptSignature(certificate: x509.X509Certificate) {
  const bytes = new Uint8Array(certificate.rawData.slice(0));
  // Decrease a trailing signature byte: preserve the TBS/key and make DER sort before the original.
  let index = bytes.length - 1;
  while (!bytes[index]) {
    index--;
  }
  bytes[index]--;
  return new x509.X509Certificate(bytes);
}

const ids = (path: readonly x509.X509Certificate[]) => Array.from(path, (certificate) => certificate.toString("hex"));

describe("crypto", () => {
  const crypto = x509.cryptoProvider.get();

  describe("chain", () => {
    const alg: RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-384",
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: 2048,
    };

    async function createCert(name: string, cert?: x509.X509Certificate, useKeyId = false) {
      const keys = await crypto.subtle.generateKey(alg, false, ["sign", "verify"]);
      expect(keys.publicKey).toBeTruthy();
      expect(keys.privateKey).toBeTruthy();

      const extensions: x509.Extension[] = [];
      const skiExt = await x509.SubjectKeyIdentifierExtension.create(keys.publicKey);
      extensions.push(skiExt);
      if (useKeyId) {
        const akiExt = await x509.AuthorityKeyIdentifierExtension.create(cert ? await cert.publicKey.export() : keys.publicKey);
        extensions.push(akiExt);
      }

      const res = await x509.X509CertificateGenerator.create({
        serialNumber: "01",
        subject: `CN=${name}`,
        issuer: cert ? cert.subject : `CN=${name}`,
        notBefore: new Date("2020/01/01"),
        notAfter: new Date("2020/01/02"),
        signingAlgorithm: alg,
        publicKey: keys.publicKey,
        signingKey: cert && cert.privateKey ? cert.privateKey : keys.privateKey,
        extensions,
      });
      res.privateKey = keys.privateKey;

      return res;
    }

    const certs = new x509.X509Certificates();

    beforeAll(async () => {
      certs.push(await createCert("Root CA")); // 0
      const root2 = await createCert("Root CA #2");
      certs.push(await createCert("Intermediate CA #1", certs[0], true)); // 1
      certs.push(await createCert("Intermediate CA #2", certs[0])); // 2
      certs.push(await createCert("Intermediate CA #1.1", certs[1], true)); // 3
      certs.push(await createCert("Intermediate CA #2.1", certs[2])); // 4
      certs.push(await createCert("Intermediate CA #1.1.1", certs[3], true)); // 5
      certs.push(await createCert("Client #1", certs[5], true)); // 6
      certs.push(await createCert("Client #2", certs[4])); // 7
      certs.push(await createCert("Odd cert", undefined, true)); // 8
      certs.push(await createCert("Intermediate CA #3", root2, true)); // 9
      certs.push(await createCert("Intermediate CA #3.1", certs[9], true)); // 10
      certs.push(await createCert("User #3.1.1", certs[10], true)); // 11
      certs.push(await createCert("Root CA #3")); // 12
      certs.push(await createCert("Intermediate CA same name")); // 13
      certs.push(await createCert("Intermediate CA same name", certs[12])); // 14
      certs.push(await createCert("Client same name", certs[14])); // 15
    });

    it("without key identifiers", async () => {
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[7]);
      expect(items.length).toBe(4);
      expect(items.map((o) => o.subject).join(",")).toBe("CN=Client #2,CN=Intermediate CA #2.1,CN=Intermediate CA #2,CN=Root CA");
    });

    it("with key identifiers", async () => {
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[6]);
      expect(items.length).toBe(5);
      expect(items.map((o) => o.subject).join(",")).toBe("CN=Client #1,CN=Intermediate CA #1.1.1,CN=Intermediate CA #1.1,CN=Intermediate CA #1,CN=Root CA");
    });

    it("uncompleted path", async () => {
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[11]);
      expect(items.length).toBe(3);
      expect(items.map((o) => o.subject).join(",")).toBe("CN=User #3.1.1,CN=Intermediate CA #3.1,CN=Intermediate CA #3");
    });

    it("single cert", async () => {
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[8]);
      expect(items.length).toBe(1);
      expect(items.map((o) => o.subject).join(", ")).toBe("CN=Odd cert");
    });

    it("self-signed cert", async () => {
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[0]);
      expect(items.length).toBe(1);
      expect(items.map((o) => o.subject).join(", ")).toBe("CN=Root CA");
    });

    it("ca with the same name and serial number (without kid)", async () => {
      const chain = new x509.X509ChainBuilder({ certificates: certs });
      const items = await chain.build(certs[15]);
      expect(items.length).toBe(3);
      expect(items.map((o) => o.subject).join(",")).toBe("CN=Client same name,CN=Intermediate CA same name,CN=Root CA #3");
    });
  });
});

describe("X509ChainBuilder.buildToAnchor", () => {
  const crypto = x509.cryptoProvider.get();
  const algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
  let rootKeys: CryptoKeyPair;
  let issuerKeys: CryptoKeyPair;
  let leafKeys: CryptoKeyPair;
  let otherKeys: CryptoKeyPair;
  let root: x509.X509Certificate;
  let otherRoot: x509.X509Certificate;
  let issuer: x509.X509Certificate;
  let leaf: x509.X509Certificate;
  let damagedIssuer: x509.X509Certificate;
  let serial = 0;

  async function issue(subject: string, keys: CryptoKeyPair, parent?: { subject: string; keys: CryptoKeyPair }, extensions: x509.Extension[] = []) {
    return x509.X509CertificateGenerator.create(
      {
        serialNumber: (++serial).toString(16).padStart(4, "0"),
        subject: `CN=${subject}`,
        issuer: parent ? `CN=${parent.subject}` : `CN=${subject}`,
        publicKey: keys.publicKey,
        signingKey: parent?.keys.privateKey || keys.privateKey,
        signingAlgorithm: algorithm,
        // Expired certificates deliberately demonstrate signature-only chain construction.
        notBefore: new Date("2020-01-01T00:00:00Z"),
        notAfter: new Date("2021-01-01T00:00:00Z"),
        extensions,
      },
      crypto,
    );
  }

  beforeAll(async () => {
    [rootKeys, issuerKeys, leafKeys, otherKeys] = await Promise.all(Array.from({ length: 4 }, () => crypto.subtle.generateKey(algorithm, false, ["sign", "verify"])));
    root = await issue("Root", rootKeys, undefined, [new x509.SubjectKeyIdentifierExtension("aa")]);
    otherRoot = await issue("Other Root", otherKeys);
    issuer = await issue("Issuer", issuerKeys, { subject: "Root", keys: rootKeys }, [new x509.SubjectKeyIdentifierExtension("01")]);
    leaf = await issue("Leaf", leafKeys, { subject: "Issuer", keys: issuerKeys }, [new x509.AuthorityKeyIdentifierExtension("01")]);
    damagedIssuer = corruptSignature(issuer);
  });

  afterEach(() => vi.restoreAllMocks());

  it("includes an anchor supplied outside the pool and uses the explicit crypto provider", async () => {
    const builder = new x509.X509ChainBuilder({ certificates: [issuer] });
    const verify = vi.spyOn(leaf, "verify");
    const path = await builder.buildToAnchor(leaf, { trustAnchors: root }, crypto);
    expect(path).toBeInstanceOf(x509.X509Certificates);
    expect(ids(path)).toEqual(ids([leaf, issuer, root]));
    expect(verify).toHaveBeenCalledWith(expect.objectContaining({ signatureOnly: true }), crypto);
  });

  it("backtracks after a signature-valid issuer leads to a dead end, preserving build() behavior", async () => {
    const builder = new x509.X509ChainBuilder({ certificates: [damagedIssuer, issuer, root] });
    expect(ids(await builder.build(leaf, crypto))).toEqual(ids([leaf, damagedIssuer]));
    const damagedVerify = vi.spyOn(damagedIssuer, "verify");
    expect(ids(await builder.buildToAnchor(leaf, { trustAnchors: root }, crypto))).toEqual(ids([leaf, issuer, root]));
    expect(damagedVerify).toHaveBeenCalledOnce();
    builder.certificates.reverse();
    expect(ids(await builder.buildToAnchor(leaf, { trustAnchors: root }))).toEqual(ids([leaf, issuer, root]));
  });

  it("deduplicates DER copies, including anchors already in the pool", async () => {
    const builder = new x509.X509ChainBuilder({ certificates: [root, issuer, new x509.X509Certificate(issuer.rawData), leaf, new x509.X509Certificate(root.rawData)] });
    expect(ids(await builder.buildToAnchor(leaf, { trustAnchors: [root, new x509.X509Certificate(root.rawData)] }))).toEqual(ids([leaf, issuer, root]));
  });

  it("returns the starting certificate when its DER equals an anchor without checking signatures", async () => {
    const copy = new x509.X509Certificate(root.rawData);
    const verify = vi.spyOn(copy, "verify");
    const path = await new x509.X509ChainBuilder().buildToAnchor(copy, { trustAnchors: root, limits: { maxDepth: 1, maxSearchSteps: 1 } });
    expect(path.length).toBe(1);
    expect(path[0]).toBe(copy);
    expect(verify).not.toHaveBeenCalled();
  });

  it("does not require a trusted anchor's self-signature", async () => {
    const anchor = corruptSignature(root);
    expect(await anchor.isSelfSigned(crypto)).toBe(false);
    const verify = vi.spyOn(anchor, "verify");
    const path = await new x509.X509ChainBuilder({ certificates: [issuer] }).buildToAnchor(leaf, { trustAnchors: anchor });
    expect(ids(path)).toEqual(ids([leaf, issuer, anchor]));
    expect(verify).not.toHaveBeenCalled();
  });

  it("does not equate an anchor with another certificate having the same subject and public key", async () => {
    const sameKey = await issue("Root", rootKeys, { subject: "Missing", keys: otherKeys });
    await expect(new x509.X509ChainBuilder().buildToAnchor(sameKey, { trustAnchors: root })).rejects.toMatchObject({ code: "NO_PATH", limit: undefined });
  });

  it("rejects partial paths and unrelated self-signed roots", async () => {
    const builder = new x509.X509ChainBuilder({ certificates: [issuer, root, otherRoot] });
    await expect(builder.buildToAnchor(leaf, { trustAnchors: otherRoot })).rejects.toMatchObject({ code: "NO_PATH" });
    await expect(builder.buildToAnchor(otherRoot, { trustAnchors: root })).rejects.toMatchObject({ code: "NO_PATH" });
    await expect(new x509.X509ChainBuilder().buildToAnchor(leaf, { trustAnchors: root })).rejects.toMatchObject({
      code: "NO_PATH",
      rejections: [expect.objectContaining({ certificate: leaf, reason: "NO_ISSUER" })],
    });
  });

  it("handles self-issued key rollover and skips an immediate issuer with the wrong key", async () => {
    const rollover = await issue("Root", issuerKeys, { subject: "Root", keys: rootKeys });
    const signer = await issue("Signer", leafKeys, { subject: "Root", keys: issuerKeys });
    expect(rollover.subject).toBe(rollover.issuer);
    expect(await rollover.isSelfSigned(crypto)).toBe(false);
    const builder = new x509.X509ChainBuilder({ certificates: [rollover, root] });
    expect(ids(await builder.buildToAnchor(signer, { trustAnchors: root }))).toEqual(ids([signer, rollover, root]));
  });

  it("continues from an untrusted self-signed certificate through a cross-certificate", async () => {
    const selfSigned = await issue("Cross", issuerKeys);
    const cross = await issue("Cross", issuerKeys, { subject: "Root", keys: rootKeys });
    expect(await selfSigned.isSelfSigned(crypto)).toBe(true);
    const builder = new x509.X509ChainBuilder({ certificates: [selfSigned, cross] });
    expect(ids(await builder.buildToAnchor(selfSigned, { trustAnchors: root }))).toEqual(ids([selfSigned, cross, root]));
  });

  it("rejects cycles without excluding alternative certificates having the same DN and key", async () => {
    const a = await issue("A", issuerKeys, { subject: "B", keys: leafKeys });
    const b = await issue("B", leafKeys, { subject: "A", keys: issuerKeys });
    const builder = new x509.X509ChainBuilder({ certificates: [a, b] });
    await expect(builder.build(a, crypto)).rejects.toThrow("Circular dependency");
    await expect(builder.buildToAnchor(a, { trustAnchors: root })).rejects.toMatchObject({
      code: "NO_PATH",
      rejections: expect.arrayContaining([expect.objectContaining({ certificate: b, candidate: a, reason: "CYCLE" })]),
    });
    const exit = await issue("A", issuerKeys, { subject: "Root", keys: rootKeys });
    builder.certificates.push(exit);
    expect(ids(await builder.buildToAnchor(a, { trustAnchors: root }))).toEqual(ids([a, b, exit, root]));
  });

  it("prioritizes anchors over matching identifiers", async () => {
    const crossRoot = await issue("Root", rootKeys, { subject: "Other Root", keys: otherKeys }, [new x509.SubjectKeyIdentifierExtension("01")]);
    const signer = await issue("Signer", leafKeys, { subject: "Root", keys: rootKeys }, [new x509.AuthorityKeyIdentifierExtension("01")]);
    const verify = vi.spyOn(signer, "verify");
    const builder = new x509.X509ChainBuilder({ certificates: [crossRoot, otherRoot] });
    expect(ids(await builder.buildToAnchor(signer, { trustAnchors: root }))).toEqual(ids([signer, root]));
    expect(verify).toHaveBeenCalledOnce();
  });

  it("prioritizes matching AKI/SKI but permits missing or mismatched identifiers", async () => {
    const mismatch = await issue("Issuer", issuerKeys, { subject: "Root", keys: rootKeys }, [new x509.SubjectKeyIdentifierExtension("02")]);
    const missing = await issue("Issuer", issuerKeys, { subject: "Root", keys: rootKeys });
    const builder = new x509.X509ChainBuilder({ certificates: [missing, mismatch, issuer] });
    expect(ids(await builder.buildToAnchor(leaf, { trustAnchors: root }))).toEqual(ids([leaf, issuer, root]));
    await Promise.all(
      [mismatch, missing].map(async (candidate) => {
        const builder = new x509.X509ChainBuilder({ certificates: [candidate] });
        expect(ids(await builder.buildToAnchor(leaf, { trustAnchors: root }))).toEqual(ids([leaf, candidate, root]));
      }),
    );
  });

  it("chooses the same DER-ordered path regardless of pool and anchor order", async () => {
    const cross = await issue("Issuer", issuerKeys, { subject: "Other Root", keys: otherKeys }, [new x509.SubjectKeyIdentifierExtension("01")]);
    const builder = new x509.X509ChainBuilder({ certificates: [cross, issuer] });
    const baseline = await builder.buildToAnchor(leaf, { trustAnchors: [root, otherRoot] });
    const expectedIssuer = [cross, issuer].sort((a, b) => (a.toString("hex") < b.toString("hex") ? -1 : 1))[0];
    expect(baseline[1]).toBe(expectedIssuer);
    await Promise.all(
      [
        [issuer, cross],
        [cross, issuer],
      ].flatMap((pool) =>
        [
          [root, otherRoot],
          [otherRoot, root],
        ].map(async (anchors) => {
          const builder = new x509.X509ChainBuilder({ certificates: pool });
          expect(ids(await builder.buildToAnchor(leaf, { trustAnchors: anchors }))).toEqual(ids(baseline));
        }),
      ),
    );
  });

  it("accepts the exact depth/step boundary and distinguishes depth truncation from a complete failure", async () => {
    const builder = new x509.X509ChainBuilder({ certificates: [issuer] });
    expect(ids(await builder.buildToAnchor(leaf, { trustAnchors: root, limits: { maxDepth: 3, maxSearchSteps: 2 } }))).toEqual(ids([leaf, issuer, root]));
    await expect(builder.buildToAnchor(leaf, { trustAnchors: root, limits: { maxDepth: 2 } })).rejects.toMatchObject({
      code: "LIMIT_EXCEEDED",
      limit: "maxDepth",
      rejections: expect.arrayContaining([expect.objectContaining({ certificate: issuer, candidate: root, reason: "DEPTH" })]),
    });
    await expect(builder.buildToAnchor(leaf, { trustAnchors: root, limits: { maxSearchSteps: 1 } })).rejects.toMatchObject({ code: "LIMIT_EXCEEDED", limit: "maxSearchSteps" });
    await expect(new x509.X509ChainBuilder().buildToAnchor(leaf, { trustAnchors: root, limits: { maxDepth: 1, maxSearchSteps: 1 } })).rejects.toMatchObject({ code: "NO_PATH" });
  });

  it("continues to a shorter alternative after a longer branch hits maxDepth", async () => {
    const bridge = await issue("Bridge", otherKeys, { subject: "Root", keys: rootKeys });
    const long = await issue("Issuer", issuerKeys, { subject: "Bridge", keys: otherKeys }, [new x509.SubjectKeyIdentifierExtension("01")]);
    const short = await issue("Issuer", issuerKeys, { subject: "Root", keys: rootKeys });
    const longVerify = vi.spyOn(long, "verify");
    const builder = new x509.X509ChainBuilder({ certificates: [short, long, bridge] });
    expect(ids(await builder.buildToAnchor(leaf, { trustAnchors: root, limits: { maxDepth: 3 } }))).toEqual(ids([leaf, short, root]));
    expect(longVerify).toHaveBeenCalledOnce();
  });

  it("caches pair verification per call while charging repeated edges to the step budget", async () => {
    const shared = await issue("Shared", rootKeys, { subject: "Dead", keys: otherKeys });
    const dead = await issue("Dead", otherKeys, { subject: "Absent", keys: leafKeys });
    const first = await issue("Issuer", issuerKeys, { subject: "Shared", keys: rootKeys });
    const second = await issue("Issuer", issuerKeys, { subject: "Shared", keys: rootKeys });
    const builder = new x509.X509ChainBuilder({ certificates: [first, second, shared, dead] });
    const verify = vi.spyOn(shared, "verify");
    await expect(builder.buildToAnchor(leaf, { trustAnchors: root, limits: { maxSearchSteps: 6 } })).rejects.toMatchObject({ code: "NO_PATH" });
    expect(verify).toHaveBeenCalledOnce();
    verify.mockClear();
    await expect(builder.buildToAnchor(leaf, { trustAnchors: root, limits: { maxSearchSteps: 5 } })).rejects.toMatchObject({ code: "LIMIT_EXCEEDED", limit: "maxSearchSteps" });
    expect(verify).toHaveBeenCalledOnce();
  });

  it("records verification exceptions separately and continues searching", async () => {
    const cause = new Error("provider cannot verify this pair");
    vi.spyOn(damagedIssuer, "verify").mockRejectedValue(cause);
    const builder = new x509.X509ChainBuilder({ certificates: [damagedIssuer] });
    await expect(builder.buildToAnchor(leaf, { trustAnchors: root })).rejects.toMatchObject({
      code: "NO_PATH",
      rejections: expect.arrayContaining([expect.objectContaining({ certificate: damagedIssuer, candidate: root, reason: "VERIFICATION_ERROR", cause })]),
    });
    builder.certificates.push(issuer);
    expect(ids(await builder.buildToAnchor(leaf, { trustAnchors: root }))).toEqual(ids([leaf, issuer, root]));
  });

  it("bounds rejection diagnostics and explicitly reports truncation", async () => {
    const candidates = await Promise.all(Array.from({ length: 70 }, () => issue("Issuer", otherKeys)));
    const builder = new x509.X509ChainBuilder({ certificates: candidates });
    const failure = await builder.buildToAnchor(leaf, { trustAnchors: root }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(x509.X509ChainBuildError);
    if (!(failure instanceof x509.X509ChainBuildError)) {
      throw failure;
    }
    expect(failure.rejections).toHaveLength(64);
    expect(failure.rejectionsTruncated).toBe(true);
    expect(failure.rejections.every((event) => event.reason === "SIGNATURE_INVALID")).toBe(true);
    expect(Object.isFrozen(failure.rejections)).toBe(true);
    builder.certificates = candidates.slice(0, 63);
    await expect(builder.buildToAnchor(leaf, { trustAnchors: root })).rejects.toMatchObject({
      rejectionsTruncated: false,
      rejections: expect.arrayContaining([expect.objectContaining({ reason: "NO_ISSUER" })]),
    });
  });

  it("snapshots the pool and anchors without mutating caller-owned arrays", async () => {
    const certificates = [issuer];
    const anchors = [root];
    const builder = new x509.X509ChainBuilder({ certificates });
    const pending = builder.buildToAnchor(leaf, { trustAnchors: anchors });
    certificates.length = 0;
    anchors.length = 0;
    expect(ids(await pending)).toEqual(ids([leaf, issuer, root]));
    await expect(builder.buildToAnchor(leaf, { trustAnchors: root })).rejects.toMatchObject({ code: "NO_PATH" });
    const frozen = Object.freeze([root]);
    builder.certificates = [issuer];
    expect(ids(await builder.buildToAnchor(leaf, { trustAnchors: frozen }))).toEqual(ids([leaf, issuer, root]));
  });

  it("exports frozen defaults and rejects empty anchors", async () => {
    expect(x509.X509ChainBuilder.defaultLimits).toEqual({ maxDepth: 16, maxSearchSteps: 10_000 });
    expect(Object.isFrozen(x509.X509ChainBuilder.defaultLimits)).toBe(true);
    await expect(new x509.X509ChainBuilder().buildToAnchor(leaf, { trustAnchors: [] })).rejects.toBeInstanceOf(TypeError);
  });

  for (const limit of ["maxDepth", "maxSearchSteps"] as const) {
    it.each([0, -1, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])(`rejects invalid ${limit}: %s`, async (value) => {
      await expect(new x509.X509ChainBuilder().buildToAnchor(leaf, { trustAnchors: root, limits: { [limit]: value } })).rejects.toBeInstanceOf(RangeError);
    });
  }

  it("preserves the reason of an already-aborted signal", async () => {
    const controller = new AbortController();
    const reason = new Error("cancelled before preparation");
    controller.abort(reason);
    const verify = vi.spyOn(leaf, "verify");
    await expect(new x509.X509ChainBuilder({ certificates: [issuer] }).buildToAnchor(leaf, { trustAnchors: root, signal: controller.signal })).rejects.toBe(reason);
    expect(verify).not.toHaveBeenCalled();
  });

  it("preserves cancellation during preparation even when the starting certificate is already trusted", async () => {
    const controller = new AbortController();
    const reason = new Error("cancelled while preparing an already-trusted certificate");
    const pending = new x509.X509ChainBuilder().buildToAnchor(root, { trustAnchors: root, signal: controller.signal });
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
  });

  it("preserves cancellation before reporting an exhausted search", async () => {
    const controller = new AbortController();
    const reason = new Error("cancelled before NO_PATH");
    const issuerName = leaf.issuer;
    vi.spyOn(leaf, "issuer", "get").mockImplementationOnce(() => {
      // Schedule cancellation after preparation, at the first traversal checkpoint.
      queueMicrotask(() => controller.abort(reason));
      return issuerName;
    });
    await expect(new x509.X509ChainBuilder().buildToAnchor(leaf, { trustAnchors: root, signal: controller.signal })).rejects.toBe(reason);
  });

  it("propagates cancellation during verification instead of recording a rejection", async () => {
    const controller = new AbortController();
    const reason = { cancelled: true };
    const verify = leaf.verify.bind(leaf);
    vi.spyOn(leaf, "verify").mockImplementationOnce(async (...args) => {
      const ok = await verify(...args);
      controller.abort(reason);
      return ok;
    });
    await expect(new x509.X509ChainBuilder({ certificates: [issuer] }).buildToAnchor(leaf, { trustAnchors: root, signal: controller.signal })).rejects.toBe(reason);
  });

  it("yields to timer cancellation even when verification resolves only through microtasks", async () => {
    const certificates = await Promise.all(Array.from({ length: 8 }, () => issue("Loop", issuerKeys)));
    for (const certificate of certificates) {
      vi.spyOn(certificate, "verify").mockResolvedValue(true);
    }
    const controller = new AbortController();
    const reason = new Error("timer cancellation");
    const timer = setTimeout(() => controller.abort(reason), 0);
    try {
      await expect(new x509.X509ChainBuilder({ certificates }).buildToAnchor(certificates[0], { trustAnchors: root, signal: controller.signal })).rejects.toBe(reason);
    } finally {
      clearTimeout(timer);
    }
  });
});
