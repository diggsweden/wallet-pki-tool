# Wallet PKI Tool

`wallet-pki-tool` generates the fixed certificates, keystores, and signed documents used by Digg wallet participants. Named wallet-role flows own the profiles, aliases, dependencies, and filenames. YAML supplies organization details, subjects, URLs, and secret references.

## Build and run

Java 25 and Maven are required:

```bash
./mvnw clean package
java -jar target/wallet-pki-tool.jar --help
```

Use [managed-authorities.yaml](examples/managed-authorities.yaml) to create managed CAs, or [existing-authorities.yaml](examples/existing-authorities.yaml) to use supplied CA files. Set the configured password environment variables or mount their password files. The CLI reads the process environment; containers can receive variables through `--env-file`.

```bash
java -jar target/wallet-pki-tool.jar init-authorities --config examples/managed-authorities.yaml
java -jar target/wallet-pki-tool.jar generate --config examples/managed-authorities.yaml --output ./generated/all
java -jar target/wallet-pki-tool.jar generate pid-issuer --config examples/managed-authorities.yaml --output ./generated/pid
```

`init-authorities` creates absent managed authorities and validates existing authorities. Repeating it preserves CA keys, certificates, and CRLs. Incomplete or invalid authority files fail. Keystore passwords are unnecessary for initialization.

`generate` loads existing authorities, creates fresh participant keys, and writes the selected roles' artifacts. It never initializes or rewrites a CA. Supplied authorities can be used directly without running initialization first.

Both commands default to all configured roles and accept explicit role names. `--output` overrides the configured output directory. The destination must not exist, including as an empty directory. Choose a new destination for each generation. `--json` prints the selected roles and, for generation, the resulting directory.

## Wallet roles

| Role | Generated artifacts |
| :--- | :--- |
| `pid-issuer` | Signing, nonce-encryption and request-encryption keys in one PKCS12 keystore; issuer registration JWT/JSON |
| `wallet-provider` | Wallet attestation signing identity and keystore |
| `verifier-access` | Relying-party access certificate, keystore and test CPS document |
| `verifier-registration` | Registration signing identity, keystore, registration JWT and environment file |
| `trust-source` | Dedicated signer, keystore/public certificate, four-role LoTE and all-valid test status list |

Each role has its own authority. PID and wallet signing certificates have distinct QC types. The LoTE contains the four participant CAs and is signed by the dedicated trust-source leaf.

Generation validates CA/key/CRL inputs before writing output. Before publishing, it checks keystore aliases, certificate chains and validity, private-key correspondence, signed document headers/signatures/payloads, and the verifier environment export. Selected roles require only their own passwords. A trust source can use four public CA files without the other participants' private keys or passwords.

## Configuration

Configure any subset of `pidIssuer`, `walletProvider`, `verifier.access`, `verifier.registration`, and `trustSource`.

- `authorityDirectory` holds managed CA files under fixed role directories. It defaults to `.wallet-pki/authorities` beside the configuration file.
- `outputDirectory` is the default generation destination. It defaults to `generated` beside the configuration file.
- `publicationBaseUrl` supplies the base for the fixed public certificate and CRL URLs.
- `organization` supplies the organization name, country, and identifier.
- An authority selects `source: managed` with `commonName`, or `source: existing` with `certificateFile`, `privateKeyFile`, and `crlFile`.
- Passwords select exactly one of `env` and `file`. Files are UTF-8; trailing line endings are removed and spaces are preserved. Empty passwords fail.
- SANs have separate DNS, IP, and URI lists. Registration metadata and document validity are typed configuration fields.
- `trustSource.lote.sequenceNumber` is supplied explicitly. Advance it when publishing a new trust list.

A separately generated trust source supplies public CA paths through `trustSource.lote.trustedAuthorities.<role>.certificateFile`. When participants are configured together, their configured authorities can supply those certificates.

All YAML file paths are relative to the configuration file. The CLI `--output` path is relative to the working directory. Authority and output directories must be separate and non-nested. Unknown fields, duplicate YAML keys, malformed SANs, and unsupported roles fail.

Leaf certificates have an 825-day lifetime capped by CA expiry. Document expiry is capped by the signer certificate. Supplied CRLs retain their revocation entries. The tool does not edit revocation entries or coordinate authority rollover.

## Output and deployment

Generation builds and validates files in a temporary sibling directory, then publishes the complete directory with an atomic rename. Failed generation removes temporary output. Private files use owner-only permissions on POSIX filesystems. Filesystems must support atomic directory renames within the destination's parent.

```text
generated/
  private/certificates/
  public/trust-source/
  public/pid-issuer/
  public/certificates/
```

The fixed keystore aliases are `pid_issuer`, `nonce-encryption`, `request-encryption`, `wallet_provider`, `verifier_access_certificate`, `registration`, and `trust_source`. Each private entry has a leaf/root certificate chain. CA private keys stay in managed authority storage or at their supplied paths and are never exported.

`public/trust-source/signed/trusted-entities.json` contains compact JWS. The status list is `public/trust-source/signed/status-list.jwt`. The verifier registration environment file defines `VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE`.

For existing Compose consumers, [compose.override.yaml](examples/compose.override.yaml) maps the generated files:

```bash
export PKI_BUNDLE=/absolute/path/to/generated
export PKI_UID="$(id -u)" PKI_GID="$(id -g)"
cd /path/to/wallet-ecosystem
podman compose -f docker-compose.yaml -f /path/to/wallet-pki-tool/examples/compose.override.yaml up -d --force-recreate
```

The Podman override requires Compose support for `!override`, preserves static trust-source assets, and maps the host user for owner-only keystore access. Deployment tooling controls which generated directory consumers use, retention, rollout, and rollback. Recreate consumers when changing their mounted output directory.

Each generation creates new application keys. Coordinate consumer rollout accordingly. To retain CA trust, use existing certificate/key/CRL files or a stable managed authority directory. Intermediate branch manifests and state snapshots are not loaded; configure the retained CA files explicitly when moving from the previous implementation.

## Development

```bash
just lint-fix
just verify
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for the code map and test strategy.
