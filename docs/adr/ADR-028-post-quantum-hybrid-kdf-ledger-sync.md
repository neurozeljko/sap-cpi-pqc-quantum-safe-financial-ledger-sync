# ADR-028: Hybrid Post-Quantum Cryptography (ML-KEM-768 & ML-DSA-65) for S/4HANA Financial Ledger Sync

## Status
Accepted & Deployed

## Context
Trillion-dollar central bank clearing messages synchronized into SAP S/4HANA Advanced Financial Closing remain subject to multi-decade regulatory confidentiality requirements. Classical RSA-4096 and ECDHE key exchanges are vulnerable to "Harvest Now, Decrypt Later" attacks executed by Cryptographically Relevant Quantum Computers (CRQCs), while SAP Cloud Integration does not yet expose native PQC primitives out of the box.

## Decision
1. **BouncyCastle NIST PQC Provider on SAP BTP JVM:** Embed BouncyCastle (`bcprov-jdk18on:1.79`) within SAP CPI Groovy runtime to execute NIST FIPS 203 (`ML-KEM-768`) key encapsulation and NIST FIPS 204 (`ML-DSA-65`) digital signatures.
2. **FIPS 140-3 Hybrid KDF Combiner:** Derive symmetric AES-256-GCM session keys via `HKDF-SHA384` over concatenated `X25519 || ML-KEM-768` shared secrets, preserving classical FIPS compliance alongside quantum resistance.
3. **Strict Anti-Downgrade Enforcement:** Reject any non-hybrid classical handshake at the integration router with `HTTP 426 Upgrade Required`.
4. **Immutable TSA Audit Trail:** Bind every sealed payload to an RFC 3161 UTC timestamp prior to ingestion into SAP S/4HANA Advanced Financial Closing.
