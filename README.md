# Wallet PKI Tool

[![License](https://img.shields.io/badge/License-CC0_1.0-blue.svg)](LICENSES/CC0-1.0.txt)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/diggsweden/wallet-pki-tool/badge)](https://securityscorecards.dev/viewer/?uri=github.com/diggsweden/wallet-pki-tool)

`wallet-pki-tool` provisions the fixed certificate hierarchies and signed documents used by the Digg wallet ecosystem. Configuration describes the participants; named Java flows determine their certificate profiles, dependencies, aliases and output files.

## Getting started

Copy [examples/ecosystem.yaml](examples/ecosystem.yaml) and set the five password environment variables named there. A password source can instead use `file: /run/secrets/keystore-password`; exactly one of `env` or `file` is required. The CLI reads the process environment, not `.env` files itself.

Build with Java 25 and Maven:

```bash
mvn package
java -jar target/wallet-pki-tool.jar init-authorities -c examples/ecosystem.yaml
java -jar target/wallet-pki-tool.jar generate -c examples/ecosystem.yaml
```

Both state and output paths, and all input file paths, are relative to the **working directory**, not the YAML file. The example writes private authority state under `.wallet-pki/` and consumer artifacts under `config/`.

For the container image, mount the workspace, pass passwords with `--env-file`, and run each command:

```bash
podman run --rm --userns=keep-id \
  -v "$PWD":/workspace:z -w /workspace --env-file .env \
  ghcr.io/diggsweden/wallet-pki-tool:latest \
  init-authorities -c examples/ecosystem.yaml

podman run --rm --userns=keep-id \
  -v "$PWD":/workspace:z -w /workspace --env-file .env \
  ghcr.io/diggsweden/wallet-pki-tool:latest \
  generate -c examples/ecosystem.yaml
```

Use an image built from this revision when trying the new configuration format.

## Explicit ecosystem roles

All five role sections are required. Selective generation limits which inputs are loaded and which outputs change; it does not change the configuration schema.

| Configuration section | Certificate hierarchy and artifacts |
| :--- | :--- |
| `pidIssuer` | Own CA → PID signing certificate and two encryption certificates; merged keystore and issuer registration JWT |
| `walletProvider` | Own CA → wallet attestation signing certificate and keystore |
| `verifier.access` | Own CA → relying-party access certificate and keystore |
| `verifier.registration` | Own CA → registration signing certificate; keystore, registration JWT and environment file |
| `trustSource` | Own CA → dedicated trust-list signing certificate; keystore, public signer certificate, LoTE and status list |

The organization name, country and identifier come from `organization`. Subject alternative names have explicit `dns`, `ip` and `uri` lists. Omitted SAN settings mean an empty list. PID signing and wallet signing use distinct QC types.

Each authority has exactly one source:

```yaml
authority:
  source: managed
  commonName: DIGG Wallet PID Issuer CA
```

Or supply an existing root, its matching EC P-256 key, and its current signed CRL:

```yaml
authority:
  source: existing
  certificateFile: /run/secrets/pid-issuer-ca.pem
  privateKeyFile: /run/secrets/pid-issuer-ca-key.pem
  crlFile: /run/secrets/pid-issuer-crl.pem
```

Existing roots are read and validated, never modified or copied into private managed state. Their public certificate and supplied CRL are published. Missing, invalid, expired or mismatched material fails.

`init-authorities` creates absent managed roots, validates complete existing state, and publishes CA certificates and CRLs. It requires no keystore passwords. Repeating it preserves all CA keys, certificates and CRLs. Incomplete state is an error. Changing an initialized managed CA's subject requires an explicit migration.

`generate` only loads authorities. It never creates or replaces a CA. Authority rotation and CRL editing are not CLI operations in this revision.

## Generation targets and dependencies

```bash
java -jar target/wallet-pki-tool.jar generate -c examples/ecosystem.yaml pid-issuer
java -jar target/wallet-pki-tool.jar generate -c examples/ecosystem.yaml verifier-access verifier-registration
java -jar target/wallet-pki-tool.jar generate -c examples/ecosystem.yaml lote status-list
```

| Target | Required inputs | Outputs updated |
| :--- | :--- | :--- |
| `pid-issuer` | PID CA/key/CRL and PID password | Three-key PID keystore, issuer registration JWT/JSON, PID CA publication |
| `wallet-provider` | Wallet CA/key/CRL and wallet password | Wallet keystore and CA publication |
| `verifier-access` | Access CA/key/CRL and access password | Access keystore and CA publication |
| `verifier-registration` | Registration CA/key/CRL and registration password | Registration keystore, JWT, environment file and CA publication |
| `trust-source` | Trust-source CA/key/CRL, signer password and four public participant CAs | New signer, LoTE, status list and trust-source CA publication |
| `lote` | Four public participant CAs, public trust-source CA and saved signer keystore/password | LoTE only |
| `status-list` | Public trust-source CA and saved signer keystore/password | Status list only |

No targets means all operations. Unknown targets fail. All required secrets and authority/signer inputs are checked before generation writes output. Individual artifacts can still fail during writing; a complete generation is not a filesystem transaction.

Participant leaf rotation does not change LoTE: it trusts the four participant **CAs**. Rotating the trust-source signer explicitly refreshes both documents. A document-only run never creates a missing signer; generate `trust-source` first.

## Consumer artifact contract

Paths below are relative to `outputDirectory`.

| Artifact | Path | PKCS#12 aliases |
| :--- | :--- | :--- |
| PID issuer | `certificates/issuer/pid_issuer.p12` | `pid_issuer`, `nonce-encryption`, `request-encryption` |
| Wallet provider | `certificates/wallet-provider/wallet_provider.p12` | `wallet_provider` |
| Verifier access | `certificates/verifier-access-certificate/verifier-access-certificate.p12` | `verifier_access_certificate` |
| Verifier registration | `certificates/verifier-registration-certificate/verifier-registration-certificate.p12` | `registration` |
| Trust-list signer | `certificates/trust-list-signer/trust_source.p12` | `trust_source` |
| Public signer certificate | `certificates/trust-list-signer/trust_source_cert.pem` | — |
| Issuer registration | `pid-issuer/issuer_wrprc.jwt`, `issuer_wrprc.json` | — |
| Verifier registration | `certificates/verifier-registration-certificate/registration_certificate.jwt`, `registration_certificate.env` | — |
| Signed LoTE | `trust-source/signed/trusted-entities.json` | — |
| Signed status list | `trust-source/signed/status-list.jwt` | — |
| Public CA material | `trust-source/<role>/ca.pem`, `revocation-list.pem` | — |

Public authority directories are `pid-issuer`, `wallet-provider`, `verifier-access-certificate`, `verifier-registration-certificate` and `trust-source`. The trust-source CRL is also published at `trust-source/revocation-list.pem`. Private CA material stays under `stateDirectory/authorities/<role>/`; never serve that directory. All PKCS#12 chains contain the leaf followed by its root.

Despite its filename, `trusted-entities.json` contains a **compact JWS**, not plain JSON. Its four service types are assigned directly from the named roles. Entity names, information URLs, postal addresses, scheme name, sequence and validity are explicit LoTE settings. The organization supplies scheme operator and territory. Both trust documents carry the dedicated signing leaf in `x5c`.

The status list currently represents an all-valid local ecosystem. It does not consume or manage revocation entries. Root CRLs are preserved when authorities are loaded.

Verifier registration settings provide the service identity, localized description and purpose, requested PID claim paths, supervisory authority and validity. The registration builder owns the fixed PID format (`dc+sd-jwt`, `urn:eudi:pid:1`), service-provider entitlement, policy OID and status index zero. `publicBaseUrl` supplies the base for `/registry`, `/privacy`, `/info`, `/support`, `/certificate-policy` and `/registration-certificate-status`. The environment file defines `VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE`.

## Code map

Read these files in order to follow an operation:

1. [`config/PkiConfiguration.java`](src/main/java/se/digg/wallet/pki/config/PkiConfiguration.java) and the named role records define the schema and its invariants. [`ConfigurationLoader`](src/main/java/se/digg/wallet/pki/config/ConfigurationLoader.java) rejects unknown fields.
2. [`application/EcosystemProvisioner.java`](src/main/java/se/digg/wallet/pki/application/EcosystemProvisioner.java) selects fixed operations, preloads required inputs and calls role flows in dependency order.
3. [`PidIssuerFlow`](src/main/java/se/digg/wallet/pki/application/PidIssuerFlow.java), [`WalletProviderFlow`](src/main/java/se/digg/wallet/pki/application/WalletProviderFlow.java), [`VerifierFlow`](src/main/java/se/digg/wallet/pki/application/VerifierFlow.java) and [`TrustSourceFlow`](src/main/java/se/digg/wallet/pki/application/TrustSourceFlow.java) describe each role's steps.
4. [`crypto/CertificateProfileIssuer.java`](src/main/java/se/digg/wallet/pki/crypto/CertificateProfileIssuer.java) owns the named X.509 profile recipes. Change extensions, key usages and certificate lifetimes here.
5. [`trustlist/LoteGenerator.java`](src/main/java/se/digg/wallet/pki/trustlist/LoteGenerator.java) builds the four explicit LoTE entries. [`RegistrationDocuments`](src/main/java/se/digg/wallet/pki/trustlist/RegistrationDocuments.java) contains typed registration payloads and protocol field mappings.
6. [`infrastructure/AuthorityStore.java`](src/main/java/se/digg/wallet/pki/infrastructure/AuthorityStore.java) owns CA initialization/loading and CRL validation; [`EcosystemLayout`](src/main/java/se/digg/wallet/pki/infrastructure/EcosystemLayout.java) owns consumer paths. Crypto, PEM and keystore mechanics stay below the role flows.

There is no certificate registry, generic profile dispatch, string reference resolution or certificate-name inference. Low-level crypto helpers are shared.

## Migrating the previous generic configuration

This is a breaking schema change. `authorities`, `certificates`, `trustLists`, arbitrary IDs, profile strings and configurable aliases/output filenames are removed. Use the example to configure the five roles. `outputDirectory` now points at the ecosystem's `config/` root, not its `certificates/` subdirectory. Target names are the fixed operations listed above.

To preserve existing trust anchors, configure each as `source: existing` with its current certificate, key and CRL. Do not initialize fresh managed roots when you intend to keep existing trust relationships. The CLI does not inspect old directories to infer a migration.

The automatic `trusted_issuers.p12` side output was removed: it is not consumed by the inspected ecosystem Compose configuration. No private trust-source PEM key is exported; the CLI signs from its PKCS#12 keystore. The registration alias is explicitly `registration`, matching the ecosystem script. Automatic `.license` sidecars are not generated.

## Development

```bash
just lint-fix
just verify
```

Tests exercise real certificate issuance, PKCS#12 contents, JWT signatures and payloads, explicit LoTE role mapping, imported authority validation, CA reuse and selective generation. They do not start the ecosystem services.
