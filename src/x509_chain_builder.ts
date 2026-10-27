import { AsnConvert } from "@peculiar/asn1-schema";
import * as asn1X509 from "@peculiar/asn1-x509";
import { equal, hex } from "@peculiar/utils";
import type { AuthorityKeyIdentifierExtension, SubjectKeyIdentifierExtension } from "./extensions";
import { cryptoProvider } from "./provider";
import type { X509Certificate } from "./x509_cert";
import { X509Certificates } from "./x509_certs";

export interface X509ChainBuilderParams {
  certificates?: X509Certificate[];
}

/** Resource limits for a single search to an explicitly trusted certificate. */
export interface X509ChainSearchLimits {
  /** Maximum certificates in a path, including the starting certificate and anchor. Default: 16. */
  maxDepth?: number;
  /** Maximum child/issuer pairs considered, including cache hits and rejected pairs. Default: 10,000. */
  maxSearchSteps?: number;
}

/** Options for {@link X509ChainBuilder.buildToAnchor}. */
export interface X509ChainBuildToAnchorParams {
  /** One or more trusted endpoint certificates, matched by their complete DER encoding. Must not be empty. */
  trustAnchors: X509Certificate | readonly X509Certificate[];
  /** Overrides for {@link X509ChainBuilder.defaultLimits}. These do not bound input parsing or pool preparation. */
  limits?: X509ChainSearchLimits;
  /** Cooperative cancellation, checked during preparation and between search operations. */
  signal?: AbortSignal;
}

/** One rejected connection or exhausted certificate encountered during a chain search. */
export interface X509ChainRejection {
  /** Certificate whose issuer was being sought. */
  certificate: X509Certificate;
  /** Candidate issuer, when the event concerns a connection. */
  candidate?: X509Certificate;
  /** Why the connection or branch could not be used. */
  reason: "NO_ISSUER" | "SIGNATURE_INVALID" | "VERIFICATION_ERROR" | "CYCLE" | "DEPTH";
  /** Original exception for VERIFICATION_ERROR. An invalid signature alone has no cause. */
  cause?: unknown;
}

/** A completed search without a confirmed path, or a search stopped by a resource limit. */
export class X509ChainBuildError extends Error {
  /** NO_PATH means all available branches were exhausted; LIMIT_EXCEEDED leaves existence of a path unknown. */
  public readonly code: "NO_PATH" | "LIMIT_EXCEEDED";
  /** Limit that prevented completion, present only for LIMIT_EXCEEDED. */
  public readonly limit?: keyof X509ChainSearchLimits;
  /** First 64 rejection events, in deterministic traversal order. */
  public readonly rejections: readonly X509ChainRejection[];
  /** Whether further rejection events were omitted. */
  public readonly rejectionsTruncated: boolean;

  /**
   * Creates a chain search error.
   * @param code Search outcome
   * @param rejections Recorded rejection events
   * @param rejectionsTruncated Whether additional events were omitted
   * @param limit Resource limit that stopped the search
   */
  public constructor(code: "NO_PATH" | "LIMIT_EXCEEDED", rejections: readonly X509ChainRejection[], rejectionsTruncated: boolean, limit?: keyof X509ChainSearchLimits) {
    super(code === "NO_PATH" ? "Cannot build a certificate chain to a trusted anchor. No path found." : `Cannot build a certificate chain to a trusted anchor. Limit exceeded: ${limit}.`);
    this.name = "X509ChainBuildError";
    this.code = code;
    this.limit = limit;
    this.rejections = Object.freeze(rejections.slice(0, 64).map((item) => Object.freeze({ ...item })));
    this.rejectionsTruncated = rejectionsTruncated || rejections.length > 64;
  }
}

/**
 * Represents a chain-building engine for X509Certificate certificates
 * @example
 * ```js
 * const chain = new x509.X509ChainBuilder({
 *   certificates: [
 *     new x509.X509Certificate(raw1),
 *     new x509.X509Certificate(raw2),
 *     // ...
 *     new x509.X509Certificate(rawN),
 *   ],
 * });
 *
 * const cert = x509.X509Certificate(raw);
 * const items = await chain.build(cert);
 * ```
 */
export class X509ChainBuilder {
  /** Frozen defaults for buildToAnchor(); existing build() calls do not use these limits. */
  public static readonly defaultLimits: Readonly<Required<X509ChainSearchLimits>> = Object.freeze({ maxDepth: 16, maxSearchSteps: 10_000 });

  public certificates: X509Certificate[] = [];

  public constructor(params: X509ChainBuilderParams = {}) {
    if (params.certificates) {
      this.certificates = params.certificates;
    }
  }

  public async build(cert: X509Certificate, crypto = cryptoProvider.get()) {
    const chain = new X509Certificates(cert);

    let current: X509Certificate | null = cert;
    // eslint-disable-next-line no-cond-assign
    while ((current = await this.findIssuer(current, crypto))) {
      // check out circular dependency
      const thumbprint = await current.getThumbprint(crypto);
      for (const item of chain) {
        const thumbprint2 = await item.getThumbprint(crypto);
        if (equal(thumbprint, thumbprint2)) {
          throw new Error("Cannot build a certificate chain. Circular dependency.");
        }
      }

      chain.push(current);
    }

    return chain;
  }

  /**
   * Finds a signature-verified path from cert to any explicitly trusted anchor, including both endpoints.
   * Searches alternative branches in deterministic depth-first order: anchors, AKI/SKI matches, then other
   * same-name issuers, with complete DER as the tie-breaker. Identifiers are hints, not hard constraints.
   * Does not validate dates, CA constraints, usage, policies, or revocation. Partial paths are never returned.
   * @param cert Starting certificate
   * @param params Trusted endpoints, resource limits, and optional cooperative cancellation
   * @param crypto WebCrypto provider. Default is from CryptoProvider
   * @throws {@link X509ChainBuildError} when no confirmed path is found or a limit prevents completion
   * @throws {@link TypeError} for an empty anchor list; {@link RangeError} for invalid limits
   * @throws The signal's reason on cancellation. An in-flight WebCrypto operation is not interrupted.
   */
  public async buildToAnchor(cert: X509Certificate, params: X509ChainBuildToAnchorParams, crypto = cryptoProvider.get()): Promise<X509Certificates> {
    // Snapshot the mutable pool before the first await. Anchors and budgets belong only to this call.
    return buildChainToAnchor(cert, this.certificates.slice(), params, crypto);
  }

  private async findIssuer(cert: X509Certificate, crypto = cryptoProvider.get()) {
    if (!(await cert.isSelfSigned(crypto))) {
      const akiExt = cert.getExtension<AuthorityKeyIdentifierExtension>(asn1X509.id_ce_authorityKeyIdentifier);
      for (const item of this.certificates) {
        if (item.subject !== cert.issuer) {
          continue;
        }

        if (akiExt) {
          if (akiExt.keyId) {
            const skiExt = item.getExtension<SubjectKeyIdentifierExtension>(asn1X509.id_ce_subjectKeyIdentifier);
            if (skiExt && skiExt.keyId !== akiExt.keyId) {
              continue;
            }
          } else if (akiExt.certId) {
            const sanExt = item.getExtension<SubjectKeyIdentifierExtension>(asn1X509.id_ce_subjectAltName);
            if (sanExt && !(akiExt.certId.serialNumber === item.serialNumber && equal(AsnConvert.serialize(akiExt.certId.name), AsnConvert.serialize(sanExt)))) {
              continue;
            }
          }
        }
        try {
          const algorithm = {
            ...item.publicKey.algorithm,
            ...cert.signatureAlgorithm,
          };
          const publicKey = await item.publicKey.export(algorithm, ["verify"], crypto);
          const ok = await cert.verify(
            {
              publicKey,
              signatureOnly: true,
            },
            crypto,
          );
          if (!ok) {
            continue;
          }
        } catch {
          continue;
        }

        return item;
      }
    }

    return null;
  }
}

interface ChainSearchNode {
  certificate: X509Certificate;
  id: string;
  anchor: boolean;
  aki?: string;
  ski?: string;
}

type ChainVerification = { ok: true } | { ok: false; reason: "SIGNATURE_INVALID" | "VERIFICATION_ERROR"; cause?: unknown };

interface ChainSearchFrame {
  node: ChainSearchNode;
  candidates: ChainSearchNode[];
  next: number;
  hasIssuer: boolean;
}

/* eslint-disable no-await-in-loop -- Preparation checkpoints and budgeted depth-first traversal must run sequentially. */
async function buildChainToAnchor(cert: X509Certificate, certificates: readonly X509Certificate[], params: X509ChainBuildToAnchorParams, crypto: Crypto): Promise<X509Certificates> {
  const anchors: readonly X509Certificate[] = Array.isArray(params.trustAnchors) ? params.trustAnchors.slice() : [params.trustAnchors as X509Certificate];
  if (!params.trustAnchors || !anchors.length) {
    throw new TypeError("At least one trust anchor is required.");
  }

  const limits = { ...X509ChainBuilder.defaultLimits };
  for (const name of ["maxDepth", "maxSearchSteps"] as const) {
    const value = params.limits?.[name];
    if (value !== undefined) {
      if (!Number.isSafeInteger(value) || value <= 0) {
        throw new RangeError(`${name} must be a positive safe integer.`);
      }
      limits[name] = value;
    }
  }

  const signal = params.signal;
  let work = 0;
  const checkpoint = async () => {
    signal?.throwIfAborted();
    // Yield a task, rather than only a microtask, so timers/UI can abort even during cache-only traversal.
    if (signal && ++work % 64 === 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      signal.throwIfAborted();
    }
  };
  signal?.throwIfAborted();

  const nodes = new Map<string, ChainSearchNode>();
  const add = (certificate: X509Certificate, anchor = false) => {
    // Hex preserves bytewise DER ordering and exact identity, without a hash collision assumption.
    const id = hex.encode(certificate.rawData);
    let node = nodes.get(id);
    if (!node) {
      node = { certificate, id, anchor };
      nodes.set(id, node);
    } else if (anchor) {
      node.anchor = true;
    }
    return node;
  };

  const start = add(cert);
  for (const anchor of anchors) {
    await checkpoint();
    add(anchor, true);
  }
  if (start.anchor) {
    signal?.throwIfAborted();
    return new X509Certificates(cert);
  }
  for (const certificate of certificates) {
    await checkpoint();
    add(certificate);
  }

  const bySubject = new Map<string, ChainSearchNode[]>();
  for (const node of nodes.values()) {
    await checkpoint();
    // Identifier extensions only rank candidates. A malformed hint must not prevent signature-based search.
    try {
      node.aki = node.certificate.getExtension<AuthorityKeyIdentifierExtension>(asn1X509.id_ce_authorityKeyIdentifier)?.keyId;
      node.ski = node.certificate.getExtension<SubjectKeyIdentifierExtension>(asn1X509.id_ce_subjectKeyIdentifier)?.keyId;
    } catch {
      // Full extension validation is outside the chain builder's contract.
    }
    const subject = node.certificate.subject;
    const group = bySubject.get(subject);
    if (group) {
      group.push(node);
    } else {
      bySubject.set(subject, [node]);
    }
  }

  const candidates = new Map<ChainSearchNode, ChainSearchNode[]>();
  const frame = (node: ChainSearchNode): ChainSearchFrame => {
    let issuers = candidates.get(node);
    if (!issuers) {
      const priority = (issuer: ChainSearchNode) => (issuer.anchor ? 0 : node.aki && node.aki === issuer.ski ? 1 : 2);
      issuers = (bySubject.get(node.certificate.issuer) || []).slice().sort((a, b) => priority(a) - priority(b) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
      candidates.set(node, issuers);
    }
    return { node, candidates: issuers, next: 0, hasIssuer: false };
  };

  const rejections: X509ChainRejection[] = [];
  let truncated = false;
  const reject = (event: X509ChainRejection) => {
    if (rejections.length < 64) {
      rejections.push(event);
    } else {
      truncated = true;
    }
  };
  const failure = (limit?: keyof X509ChainSearchLimits) => new X509ChainBuildError(limit ? "LIMIT_EXCEEDED" : "NO_PATH", rejections, truncated, limit);
  const verified = new Map<ChainSearchNode, Map<ChainSearchNode, ChainVerification>>();
  const verify = async (child: ChainSearchNode, issuer: ChainSearchNode): Promise<ChainVerification> => {
    let cache = verified.get(child);
    if (!cache) {
      cache = new Map();
      verified.set(child, cache);
    }
    let result = cache.get(issuer);
    if (!result) {
      try {
        const algorithm = { ...issuer.certificate.publicKey.algorithm, ...child.certificate.signatureAlgorithm };
        const publicKey = await issuer.certificate.publicKey.export(algorithm, ["verify"], crypto);
        signal?.throwIfAborted();
        const ok = await child.certificate.verify({ publicKey, signatureOnly: true }, crypto);
        result = ok ? { ok: true } : { ok: false, reason: "SIGNATURE_INVALID" };
      } catch (cause) {
        signal?.throwIfAborted();
        result = { ok: false, reason: "VERIFICATION_ERROR", cause };
      }
      signal?.throwIfAborted();
      cache.set(issuer, result);
    }
    return result;
  };

  const path = [start];
  const active = new Set(path);
  const stack = [frame(start)];
  let steps = 0;
  let depthExceeded = false;
  while (stack.length) {
    await checkpoint();
    signal?.throwIfAborted();
    const current = stack[stack.length - 1];
    if (current.next === current.candidates.length) {
      if (!current.hasIssuer) {
        reject({ certificate: current.node.certificate, reason: "NO_ISSUER" });
      }
      stack.pop();
      active.delete(current.node);
      path.pop();
      continue;
    }
    if (steps === limits.maxSearchSteps) {
      throw failure("maxSearchSteps");
    }
    steps++;
    const issuer = current.candidates[current.next++];
    const event = { certificate: current.node.certificate, candidate: issuer.certificate };
    if (active.has(issuer)) {
      reject({ ...event, reason: "CYCLE" });
      continue;
    }
    const result = await verify(current.node, issuer);
    signal?.throwIfAborted();
    if (!result.ok) {
      reject({ ...event, reason: result.reason, cause: result.cause });
      continue;
    }
    current.hasIssuer = true;
    if (path.length === limits.maxDepth) {
      depthExceeded = true;
      reject({ ...event, reason: "DEPTH" });
      continue;
    }
    path.push(issuer);
    if (issuer.anchor) {
      return new X509Certificates(path.map((node) => node.certificate));
    }
    active.add(issuer);
    stack.push(frame(issuer));
  }

  throw failure(depthExceeded ? "maxDepth" : undefined);
}
/* eslint-enable no-await-in-loop */
