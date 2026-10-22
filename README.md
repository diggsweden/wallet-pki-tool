# Wallet PKI Tool

`wallet-pki-tool` plans, maintains, and verifies the certificates, keystores, and signed documents used by a wallet environment. It runs as a Java 25 CLI or a container.

The configuration describes authorities, identities, documents, truststores, and consumer exports separately. The tool preserves valid existing material, resolves dependencies during renewal and rotation, and publishes a verified generation through one atomic `current` pointer.

## Build and run

```bash
./mvnw clean package
java -jar target/wallet-pki-tool.jar --help
```

[examples/local.yaml](examples/local.yaml) provides the local ecosystem configuration. Its keystore passwords come from the environment variables named in the file. A container can receive them through `--env-file`; the CLI does not source shell scripts or `.env` files.

Create and inspect a plan before applying it:

```bash
java -jar target/wallet-pki-tool.jar plan --config examples/local.yaml --json > plan.json
java -jar target/wallet-pki-tool.jar apply --plan plan.json
java -jar target/wallet-pki-tool.jar verify --config examples/local.yaml
```

Planning reads configuration, certificate metadata, and declared static files. It creates no directories, generates no keys, and resolves no password values. The plan names the required secret references. Applying a saved plan rejects changed configuration, static inputs, or committed generations.

For an operation that plans and applies immediately:

```bash
java -jar target/wallet-pki-tool.jar ensure --config examples/local.yaml
java -jar target/wallet-pki-tool.jar renew --config examples/local.yaml identity:pid-issuer
java -jar target/wallet-pki-tool.jar rotate --config examples/local.yaml identity:verifier-registration-certificate
```

Use `--json` for machine-readable plans and reports. Passwords and private keys are excluded from those results.

## Lifecycle

| Operation | Behavior |
| :--- | :--- |
| `plan` | Describe `ensure` changes, or select `--operation renew` / `--operation rotate` with explicit identity targets. |
| `apply --plan FILE` | Apply the inspected JSON plan after checking that its inputs are still current. |
| `ensure` | Initialize a complete environment, reuse valid material, and renew changed or due artifacts. An unchanged environment reuses its generation. |
| `renew` | Replace certificates while preserving existing identity keys. Explicit identity targets are required. |
| `rotate` | Replace all keys belonging to the selected identity, then rebuild dependent documents and truststores. |
| `verify` | Check the committed generation's digests, certificate/key correspondence, chains, roles, signed payloads, and truststores without writing files. |

Targets use qualified references: `authority:ID`, `identity:ID`, `document:ID`, and `truststore:ID`. Initialize the complete environment before selecting individual targets. Changes to unselected configuration must be reconciled with `ensure` first.

Dependencies follow references. Rotating a registration identity rebuilds its registration JWT and exported environment value. A LoTE containing the unchanged issuing CA remains unchanged. Rotating the LoTE signer rebuilds documents signed by that identity.

Authority creation requires explicit `create: true`. Imported authorities require both `keyFile` and `certFile`; missing or mismatched material fails. Existing trust anchors are pinned by certificate fingerprint, including when temporarily removed from configuration. Authority subject changes and replacement trust anchors require a separately coordinated rollover and are rejected by the identity rotation command.

## Configuration schema

Schema version 1 is strict: unknown fields, duplicate YAML keys, unsupported profiles, unresolved references, and conflicting export paths are rejected. Relative paths are resolved against the configuration file, independently of the working directory. State and output directories must be separate and non-nested.

The complete examples are [local.yaml](examples/local.yaml) and [stage.yaml](examples/stage.yaml).

| Field | Responsibility |
| :--- | :--- |
| `schemaVersion` | Required; currently `1`. |
| `environment` | Environment identifier recorded in plans and manifests. |
| `stateDir` | Persistent private state, including authority keys and encrypted identity stores. |
| `outputDir` | Versioned consumer bundles and their `current` pointer. |
| `authorities` | Authority ID, subject, explicit creation/import policy, and optional certificate/CRL publication URLs. |
| `identities` | Certificate profile, issuing authority, subject, SANs, alias, password reference, validity, and renewal window. |
| `documents` | Document type, signing identity, validity, and explicit payload inputs. |
| `trustStores` | Explicit certificate references, consumer aliases, and password reference. |
| `exports` | Explicit source, format, destination, and optional environment variable name. |

An identity supplies exactly one of `passwordEnv` and `passwordFile`. Password files are read as UTF-8 with trailing line endings removed. Empty passwords are rejected. Passwords remain external to YAML and reports. Keystore and truststore aliases use lowercase letters, digits, underscores, and hyphens to match PKCS12 alias handling.

Supported identity profiles are `pid-issuer-service`, `wallet-provider-service`, `relying-party-access`, `relying-party-registration`, `trust-source-signer`, `encryption`, and `service`. SANs support DNS names, IP literals, and URIs; explicit `DNS:`, `IP:`, and `URI:` prefixes are available. The PID profile owns its signing, nonce-encryption, and request-encryption keys together. Certificate expiry is capped by the issuing authority's expiry.

Identity validity defaults to 825 days; document validity defaults to 365 days. `renewBeforeDays` defines the advance renewal window. Public URLs, relying-party metadata, subjects, and claims belong to environment configuration.

Documents have one of three types:

- `lote`: requires explicit entity references and roles (`pid`, `wallet`, `wrpac`, `wrprc`), scheme name/operator, and territory. Roles are never inferred from certificate names. Its sequence number advances when rebuilt.
- `registration`: signs configured `claims`; issue and expiry times are calculated by the tool.
- `status-list`: signs the configured URL and optional compressed `statusBits`. The default is an empty development status list. Configured bits are signed as supplied; this CLI does not maintain a live revocation registry.

Each document's `signer` references an identity, whose certificate chain is embedded in the JWS header. A CA and a document signing identity are distinct resources. Document validity is capped by signer certificate expiry.

## Export bundles

```text
outputDir/
  current -> generations/GENERATION
  generations/GENERATION/
    manifest.json
    public/
      trust-source/
      pid-issuer/
      certificates/
    private/
      certificates/
```

Every generation is built in isolated staging directories and verified before publication. The state snapshot is completed before `current` is atomically replaced. Required generation failures preserve the previous current bundle. Concurrent writers are rejected. Filesystems must support symbolic links and atomic renames within each configured root.

The manifest records the tool/configuration version, generation, environment, creation time, resource fingerprints and expiry times, and file digests. `verify` needs the relevant passwords to inspect the encrypted stores. It also checks public artifact contracts and detects altered files.

| Export format | Source | Destination |
| :--- | :--- | :--- |
| `pkcs12` | Identity or truststore | Under `private/` |
| `certificate` | Authority or identity | Under `public/` |
| `crl` | Authority | Under `public/` |
| `compact` | Signed document | Under `public/` |
| `env` | Signed document; also requires `variable` | Under `public/` |
| `json` | Decoded document header and payload | Under `public/` |
| `file` | Explicit `file:PATH` static input | Under `public/` |

The legacy `trusted-entities.json` filename contains compact JWS. Use the separate decoded JSON export for `jq` inspection. Exported artifacts and the manifest receive SPDX `.license` companions.

Private exports use owner-only file permissions on POSIX filesystems. Authority private keys remain in `stateDir` and are never exported. Keep persistent state available across CI invocations and retain it separately from deployable bundles. Previous generations are retained; retention and coordinated consumer rollout belong to the deployment pipeline.

## Local ecosystem integration

The local example preserves keystore aliases, registration environment variable names, trust-source paths, and issuer registration files expected by `wallet-ecosystem`.

Use the immutable bundle path printed by `ensure` or `apply`. [examples/compose.override.yaml](examples/compose.override.yaml) maps those outputs into the existing consumers:

```bash
export PKI_BUNDLE=/absolute/path/to/reported/generation
export PKI_UID="$(id -u)" PKI_GID="$(id -g)"
cd /path/to/wallet-ecosystem
podman compose -f docker-compose.yaml -f /path/to/wallet-pki-tool/examples/compose.override.yaml up -d --force-recreate
```

The Podman override requires Compose support for `!override` and maps the current host user into keystore consumers so they can read owner-only private exports. Recreate consumers after switching generations so file mounts and environment values use the same bundle. The override preserves the ecosystem's static trust-source assets. Traefik's mkcert TLS certificate remains managed by the existing local workflow.

## Sandbox and stage

The stage example uses supplied CA key/certificate files and password files under `/run/secrets/wallet-pki/`. Adjust those mount paths and all example URLs/metadata for the target environment. The tool runs without cluster credentials and produces a versioned bundle for the existing deployment pipeline.

Use a stable, private state location and a single state/output pair per environment. Publish `public/` through the trust source and deliver the required `private/` files through the established secret-management workflow. Stage preparation must retain the configured trust anchors rather than bootstrap new ones on each CI run.

## Migrating the Bash or previous Java configuration

1. Inventory the consumer aliases, signing identities, trust anchors, published URLs, registration claims, and mounted filenames.
2. Translate these into schema version 1. Legacy `certificates`, `trustLists`, and `signerAuthority` configuration is rejected. `generate` remains an alias for `ensure` using the new schema.
3. Import existing CA key/certificate pairs explicitly to preserve trust anchors. Existing application keystores are not imported automatically; initial identity issuance creates replacement application keys and requires a coordinated consumer rollout.
4. Declare every JWT, keystore, truststore, certificate/CRL publication, static input, and environment export. Neighboring directories no longer enable implicit output.
5. Generate into isolated state/output directories, verify the artifacts, and run ecosystem acceptance tests against those outputs before changing consumers.

Certificate profiles encode this project's expected behavior. Profile changes should be checked against the applicable specifications as well as consumer interoperability tests; the migrated scripts are an artifact inventory rather than a conformance oracle.

## Development

```bash
just install
just lint-fix
just verify
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for the module interfaces and verification strategy.
