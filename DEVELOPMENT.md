# Development Guide

Use Java 25, Maven, `mise`, and `just`. Run `npm ci` for the XML formatter.

## Follow generation

1. `WalletPkiCli` exposes `init-authorities` and `generate`, with configuration, role selection, and JSON reporting. Generation also accepts `--output`.
2. `WalletPkiGenerator` loads the selected authorities and passwords, invokes named role flows, validates the written artifacts, and publishes the output directory.
3. `PidIssuerFlow`, `WalletProviderFlow`, `VerifierFlow`, and `TrustSourceFlow` each generate their complete artifact set using fresh participant keys.
4. `CertificateProfileIssuer` owns the fixed X.509 recipes. `RegistrationDocuments` owns typed PID/verifier registration payloads. `LoteGenerator` assigns the four trust roles explicitly.
5. `AuthorityStore` initializes absent managed CAs separately and loads validated authorities for generation. `IdentityStores` handles PKCS12 assembly and validation. `ArtifactLayout` owns fixed consumer paths.
6. `OutputDirectory` handles temporary output, cleanup, and publication to a fresh destination. `ArtifactFiles` owns file permissions and basic filesystem operations.

The tool has no lifecycle state, manifests, generation history, automatic renewal, or saved plans. CA files are its only persistent private inputs. Deployment labels never select application behavior. Time and secret lookup have explicit seams; cryptography and filesystem behavior are exercised directly.

## Verification

```bash
just test
just lint-fix
just verify
```

CLI component tests cover authority initialization/reuse, fresh participant keys, consumer aliases and chains, signed documents, selective inputs, supplied CRLs, and refusing existing output. Filesystem integration tests cover staging cleanup and publication. Strict configuration has integration tests. Existing crypto tests cover the certificate recipes and cryptographic primitives.

Keep assertions on the consumer artifact contract. When removing a feature, remove its obsolete tests and retain the relevant generation contracts. Run the real `wallet-ecosystem` acceptance suite separately when changing profiles or consumer outputs; tests here never restart existing consumers.
