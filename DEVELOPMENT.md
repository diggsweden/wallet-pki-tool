# Development Guide

Java 25, Maven, `mise`, and `just` are required. Run `npm ci` for the XML formatter.

## Follow an operation

1. `cli/WalletPkiCli` exposes `ensure`, `renew`, `rotate`, and `verify`. It parses named roles and renders `ProvisioningReport`.
2. `WalletProvisioner` loads typed configuration, coordinates the fixed role flows, checks lifecycle metadata, resolves required secrets, and stages a generation under a writer lock. Authority creation follows its explicit source configuration.
3. `PidIssuerFlow`, `WalletProviderFlow`, `VerifierFlow`, and `TrustSourceFlow` own their certificate recipes, key lifecycles, documents, and dependencies. Add a wallet requirement to its owning flow.
4. `CertificateProfileIssuer` owns the named X.509 recipes. `RegistrationDocuments` owns typed PID/verifier payloads. `LoteGenerator` assigns the four wallet trust roles explicitly.
5. `AuthorityStore`, `IdentityStores`, and `ArtifactLayout` own persistence mechanics and fixed consumer paths. `ArtifactStore` owns hashes, isolated staging, and atomic publication.

Configuration represents deployment values; deployment names never select application behavior. The implementation owns the wallet relationships and output contract. There is no generic resource graph, configurable export registry, or saved-plan format.

Time and secret resolution have explicit seams. Cryptography and filesystem behavior are exercised directly. Generation has no network or cluster transport.

## Verification

```bash
just test
just lint-fix
just verify
```

CLI component tests exercise managed and supplied authorities with real keys, certificates, PKCS12 stores, JWTs, and temporary directories. They cover fixed aliases, repeat execution, key-preserving renewal, explicit rotation, document-only renewal, imported authorities/CRLs, selective secrets, rollback, tampering, and writer locking. Integration tests cover strict YAML and relative paths.

Keep tests on observable wallet contracts. Replacing the internal lifecycle implementation should not require rewriting consumer assertions. Run the real `wallet-ecosystem` acceptance suite separately when changing profiles or consumer outputs; tests in this repository never restart existing consumers.
