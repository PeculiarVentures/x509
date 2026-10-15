## 2025-02-18 - X.509 Chain Validation Bypass
**Vulnerability:** X509ChainBuilder constructed chains using issuers that were not CAs (BasicConstraints cA=false) or lacked keyCertSign usage.
**Learning:** Chain building logic must explicitly validate certificate constraints (BasicConstraints, KeyUsage) of potential issuers, not just signature verification.
**Prevention:** Enforce BasicConstraints cA=true and KeyUsage keyCertSign checks when traversing the certification path.
