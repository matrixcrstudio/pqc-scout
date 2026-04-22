# PQC-Scout

**An open post-quantum cryptography migration scanner for the European digital commons.**

The transition to post-quantum cryptography is now a regulatory obligation for several hundred thousand European entities under NIS2, DORA, and the Cyber Resilience Act. Commercial assessment tools are US-vendor-locked and enterprise-priced. Existing open-source tools address single cryptographic surfaces — TLS *or* source code *or* dependencies — but none unify.

PQC-Scout closes this gap.

## What it does

Given a target — a set of domains, a stack description, or a requirements file — PQC-Scout:

1. **Enumerates cryptographic surfaces** across ten infrastructure categories: TLS certificates, code signing, storage encryption, key exchange, firmware integrity, API authentication, VPN tunnels, email signing, PKI hierarchy, and hardware keys.
2. **Scores each surface** against a Q-Day horizon model aligned with NIST IR 8547 and Mosca's theorem — classifying exposure as `CRITICAL`, `HIGH`, `MONITOR`, or `SAFE`.
3. **Emits a prioritized, phased migration roadmap** citing NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and CISA CNSA 2.0 milestones.
4. **Exports a machine-readable crypto-SBOM** — CycloneDX 1.6 crypto-asset schema plus OASIS CSAF 2.0 advisory — suitable for regulatory submission.

## Status

Early public release. A working Python prototype (~800 lines) is being carved out of a private research codebase, scrubbed of internal-project lexicon, and hardened for production public use. Initial public source lands at Milestone 1.

## Roadmap

| Milestone | Deliverable |
|---|---|
| M1 | Public source under Apache-2.0; standalone Python packaging; WCAG 2.1 AA documentation site |
| M2 | LLM-independent deterministic surface extractor |
| M3 | CycloneDX 1.6 + OASIS CSAF 2.0 crypto-SBOM exporter |
| M4 | Transitive supply-chain scanner (pip, cargo, npm, go) |
| M5 | CI integration — GitHub Action, GitLab CI template, pre-commit hook |
| M6 | Pilot adoption with European FOSS projects; standards-body engagement (CycloneDX, ENISA PQC working group) |

## Regulatory alignment

| Framework | PQC-Scout contribution |
|---|---|
| EU NIS2 Directive (2022/2555) Art. 21 | Cryptographic-control inventory and migration evidence |
| EU DORA (2022/2554) Art. 9 | ICT cryptographic risk assessment output |
| EU Cyber Resilience Act (2024/2847) Annex I | Crypto-SBOM in machine-readable format |
| ENISA PQC Integration Roadmap (2023) | Reference implementation of the recommended inventory-and-plan approach |
| NIST FIPS 203 / 204 / 205 | Recommended migration targets per surface |
| NIST IR 8547 | Q-Day horizon model and migration guidance |
| CISA CNSA 2.0 | Milestone alignment for critical-infrastructure operators |

## License

[Apache License 2.0](./LICENSE).

## Maintainer

Matrix CR Studio — Pablo Ramirez · `pablo@matrixcr.ai` · `github.com/pabl0ramirez`

## Contributing

Contributions, issues, and pilot-adoption discussions are welcome once the Milestone 1 public source lands. Opening issues before that point to flag use cases, regulatory concerns, or integration interest is encouraged.
