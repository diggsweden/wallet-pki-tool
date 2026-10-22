# Development Guide

## Prerequisites

- Java 25 and Maven 3.9+.
- `mise` and `just` for the shared verification recipes.
- Node dependencies installed with `npm ci` for XML formatting.

## Module interfaces

The generation module exposes three operations: `plan`, `apply`, and `verify`. `PkiEngine` returns immutable plans/reports and owns lifecycle policy. The CLI translates arguments and renders results.

- `ConfigurationLoader` parses a safe, strict YAML schema and resolves paths against the source file. SnakeYAML handles safe syntax loading; Jackson maps the result into immutable records.
- `GenerationPlanner` selects changes from configuration, explicit references, existing metadata, and an injected clock. It never resolves passwords or writes files.
- `IdentityIssuer` owns key generation, profile-specific auxiliary keys, certificate chains, keystore assembly, and key/certificate verification.
- `SignedDocumentGenerator` builds registration, LoTE, and status-list payloads and verifies signatures, chains, lifetimes, and configured payload contracts.
- `ArtifactStore` owns state/export paths, writer locking, staging, file digests, and atomic publication through a single pointer.

Composition happens in the generation module. Environment lookup and time have explicit seams. Cryptography is exercised directly; filesystem tests use temporary directories. There is no network or cluster transport in generation.

## Verification

```bash
just test
just lint-fix
just verify
```

CLI component tests exercise the shipped local configuration with real keys, certificates, keystores, documents, and filesystem storage. They assert consumer aliases, registration headers/chains, explicit LoTE roles, repeat execution, renewal/rotation, rollback on generation failure, and tamper detection.

Integration tests cover strict configuration, relative paths, saved-plan freshness, imported authorities, missing/mismatched material, writer locking, and renewal dependencies. Keep assertions on observable contracts rather than reproducing artifact assembly inside tests.

Run the real `wallet-ecosystem` acceptance suite separately against generated bundles when updating a profile or consumer export contract. Do not regenerate an existing environment's keys or restart its consumers as a side effect of a unit or component test.
