# PQC-Scout

**An open post-quantum cryptography migration scanner.**

The transition to post-quantum cryptography is now a regulatory obligation for several hundred thousand European entities under NIS2, DORA, and the Cyber Resilience Act. Commercial assessment tools are US-vendor-locked and enterprise-priced. Existing open-source tools address single cryptographic surfaces — TLS *or* source code *or* dependencies — but none unify.

PQC-Scout closes this gap.

## What it does

Given a target — a set of domains, a stack description, or a requirements file — PQC-Scout:

1. **Enumerates cryptographic surfaces** across ten infrastructure categories: TLS certificates, code signing, storage encryption, key exchange, firmware integrity, API authentication, VPN tunnels, email signing, PKI hierarchy, and hardware keys.
2. **Scores each surface** against a Q-Day horizon model aligned with NIST IR 8547 and Mosca's theorem — classifying exposure as `CRITICAL`, `HIGH`, `MONITOR`, or `SAFE`, with harvest-now-decrypt-later tiering driven by the earliest-credible horizon.
3. **Emits a prioritized, phased migration roadmap** citing NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), and CISA CNSA 2.0 milestones.
4. **Applies sector-aware retention priors** — financial (15y), healthcare (30y), national-security (25y), and genomic/germline data, whose effectively unbounded confidentiality horizon makes every classical asymmetric surface `CRITICAL` by construction.

## Install

```bash
pip install .           # core: deterministic extraction, TLS scan, scoring, roadmap
pip install .[llm]      # optional: LLM-assisted surface extraction
```

Python ≥ 3.10. Core dependencies: `pydantic` only.

## Usage

```bash
# Assess a stack description (deterministic extraction — default)
pqc-scout assess --target "ExampleCo" --stack "nginx TLS 1.3, RSA-2048 code signing, AES-128 backups"

# Stack from a file, with a sector retention prior
pqc-scout assess -t "GenomicsLab" -s ./stack.txt --sector genomic

# Live TLS scan (authorized targets only — passive handshake, no probing)
pqc-scout scan example.org example.com

# Saved reports
pqc-scout list
pqc-scout score   -r <report-id>
pqc-scout roadmap -r <report-id>
pqc-scout status
```

LLM-assisted extraction (`--llm`) requires the `llm` extra and `ANTHROPIC_API_KEY`. It fails loud — a truncated or invalid model response aborts the assessment rather than silently degrading to the deterministic baseline.

## Design principles

- **Deterministic by default.** The regex extractor only reports what it can literally match, and says so. LLM extraction is opt-in and never a silent fallback in either direction.
- **Sector priors are floors, never ceilings.** A sector hint can only raise exposure severity — the safe direction for a security tool.
- **Grover is not Shor.** The earliest-credible horizon compression (Regev 2023; Ragavan–Vaikuntanathan, CRYPTO 2024; Gidney 2025) applies to asymmetric primitives only; symmetric/hash horizons are deliberately left nominal.
- **Passive scanning.** The TLS scanner performs a standard handshake against hosts you name. No enumeration, no downgrade probing.

## Roadmap

| Milestone | Deliverable |
|---|---|
| M1 | ✅ Public source under Apache-2.0; standalone Python packaging |
| M2 | LLM-independent deterministic surface extractor for real configs (nginx/apache TLS, OpenSSH, package-signing metadata, container provenance) |
| M3 | CycloneDX 1.6 crypto-asset SBOM + OASIS CSAF 2.0 advisory export |
| M4 | Transitive supply-chain scanner (pip, cargo, npm, go) |
| M5 | CI integration — GitHub Action, GitLab CI template, pre-commit hook |
| M6 | Pilot adoption with European FOSS projects; standards-body engagement |

## Regulatory alignment

| Framework | PQC-Scout contribution |
|---|---|
| EU NIS2 Directive (2022/2555) Art. 21 | Cryptographic-control inventory and migration evidence |
| EU DORA (2022/2554) Art. 9 | ICT cryptographic risk assessment output |
| EU Cyber Resilience Act (2024/2847) Annex I | Machine-readable crypto inventory (SBOM export at M3) |
| ENISA PQC Integration Roadmap | Reference implementation of the inventory-and-plan approach |
| NIST FIPS 203 / 204 / 205 | Recommended migration targets per surface |
| NIST IR 8547 | Q-Day horizon model and migration guidance |
| CISA CNSA 2.0 | Milestone alignment for critical-infrastructure operators |

## License

[Apache License 2.0](./LICENSE).

## Maintainer

Matrix CR Studio — Pablo Ramirez · `pablo@matrixcr.ai`

## Contributing

Contributions, issues, and pilot-adoption discussions are welcome — especially use cases, regulatory concerns, and integration interest from projects handling long-retention data (genomics, health, civic identity).
