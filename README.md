# Wallet PKI Tool

`wallet-pki-tool` maintains the fixed certificate hierarchies and signed documents used by Digg wallet participants. Named Java flows own the certificate profiles, aliases, dependencies, and consumer filenames. YAML supplies deployment values.

## Build and run

```bash
./mvnw clean package
java -jar target/wallet-pki-tool.jar --help
```

Configure the wallet roles to provision and how each authority is supplied. The same commands apply to every deployment. Any subset of roles can be configured.

The examples are [managed-authorities.yaml](examples/managed-authorities.yaml) and [existing-authorities.yaml](examples/existing-authorities.yaml). Set the password environment variables or mount the password files named there. The CLI reads the process environment; a container can receive variables through `--env-file`.

```bash
java -jar target/wallet-pki-tool.jar ensure --config examples/managed-authorities.yaml
java -jar target/wallet-pki-tool.jar verify --config examples/managed-authorities.yaml
java -jar target/wallet-pki-tool.jar ensure wallet-provider --config examples/existing-authorities.yaml
java -jar target/wallet-pki-tool.jar rotate pid-issuer --config examples/managed-authorities.yaml
```

Use `--json` to report the immutable bundle path, generation, environment, and operations performed for each role.

## Wallet roles

| Role | Owned artifacts |
| :--- | :--- |
| `pid-issuer` | PID signing key, nonce-encryption key, request-encryption key, combined keystore, and issuer registration JWT/JSON |
| `wallet-provider` | Wallet attestation signing identity and keystore |
| `verifier-access` | Relying-party access identity, keystore, and test CPS document |
| `verifier-registration` | Registration signing identity, keystore, registration JWT, and environment export |
| `trust-source` | Dedicated signing identity, signer keystore/public certificate, four-role LoTE, and all-valid test status list |

Each role has its own authority. The PID and wallet signing recipes have distinct QC types. The LoTE trusts the four participant CAs, so rotating a participant leaf leaves it unchanged. Rotating the trust-source signer refreshes both trust documents.

Aliases, certificate profile recipes, protocol constants, and output paths live in code. Registration metadata, organization details, SANs, publication URLs, and secret references come from configuration. DNS, IP, and URI SANs have separate fields.

## Lifecycle

| Operation | Behavior |
| :--- | :--- |
| `ensure` | Initialize missing material, reuse valid material, and renew changed or due certificates while retaining keys. Refresh due documents independently. |
| `renew ROLE...` | Reissue the selected roles' certificates with their existing keys and rebuild their documents. |
| `rotate ROLE...` | Replace the selected roles' keys and rebuild their complete artifact sets. |
| `verify` | Check committed bytes, CA pins/CRLs, certificate chains, keystore aliases and key correspondence, signatures, payloads, and environment exports. |

`ensure` and `verify` default to configured roles. Every operation can select roles explicitly. Renewal and rotation require explicit role names. A selected operation reads only its required secrets and leaves previously published unrelated role artifacts unchanged.

Unchanged `ensure` reuses the same generation without keystore passwords. Full `verify` needs the selected roles' passwords to inspect their encrypted stores. Password files are UTF-8; trailing line endings are removed and spaces are preserved. Empty passwords fail.

Leaf certificates have an 825-day lifetime capped by the issuing authority. Certificates and documents renew 30 days before expiry. Configured document lifetimes must cover that window; generated documents are capped by the signer's expiry. LoTE sequence numbers advance automatically when refreshed. Authorities unable to cover the renewal window require a separately coordinated rollover.

Authorities are pinned by certificate fingerprint. Missing managed material, changed managed subjects, mismatched imported keys, expired CRLs, and replacement trust anchors fail. Supplied CRLs retain their revocation entries when published; the CLI does not operate a revocation registry. Imported authority private keys remain at their supplied paths and are never copied into state or consumer bundles.

## Configuration

Schema version `2` uses named sections: `pidIssuer`, `walletProvider`, `verifier.access`, `verifier.registration`, and `trustSource`. Configure only the roles needed for the operation.

Every authority uses either `source: managed` with `commonName`, or `source: existing` with `certificateFile`, `privateKeyFile`, and `crlFile`. `managed` explicitly permits `ensure` to create an absent authority. `existing` always requires the supplied material and never creates a replacement. Both preserve initialized trust anchors. Each password reference selects exactly one of `env` and `file`.

The free-form `environment` value labels reports and binds persistent state to its configuration. It does not select commands, roles, or authority policy.

`publicationBaseUrl` is the trust-source base used by the fixed certificate/CRL publication paths. Set it to the target environment. All filesystem paths are relative to the YAML file. State and output roots must be separate and non-nested. Unknown fields, duplicate YAML keys, malformed SANs, and unsupported roles fail.

A trust source may be provisioned independently. Supply the four public CA files through `trustSource.lote.trustedAuthorities.<role>.certificateFile`, alongside each entity's metadata. Those participants' private keys and keystore passwords are unnecessary. When participants are configured together, the LoTE can use their configured authorities directly.

## Publication and consumer contracts

Each operation builds and verifies an isolated generation before replacing one `current` symlink:

```text
outputDirectory/
  current -> generations/GENERATION
  generations/GENERATION/
    manifest.json
    private/certificates/
    public/trust-source/
    public/pid-issuer/
    public/certificates/
```

The reported bundle path identifies the immutable generation to deploy. Private files use owner-only permissions on POSIX filesystems. Persistent state holds managed CA keys, public identity certificates, authority pins, and lifecycle metadata. Previously published generations are retained. A failed operation preserves the previous current bundle; concurrent writers fail. Filesystems must support symlinks and atomic renames within each root.

| Artifact | Path inside the bundle | Alias |
| :--- | :--- | :--- |
| PID issuer | `private/certificates/issuer/pid_issuer.p12` | `pid_issuer`, `nonce-encryption`, `request-encryption` |
| Wallet provider | `private/certificates/wallet-provider/wallet_provider.p12` | `wallet_provider` |
| Verifier access | `private/certificates/verifier-access-certificate/verifier-access-certificate.p12` | `verifier_access_certificate` |
| Verifier registration | `private/certificates/verifier-registration-certificate/verifier-registration-certificate.p12` | `registration` |
| Trust signer | `private/certificates/trust-list-signer/trust_source.p12` | `trust_source` |
| Issuer registration | `public/pid-issuer/issuer_wrprc.jwt` and `.json` | — |
| Verifier registration | `public/certificates/verifier-registration-certificate/registration_certificate.jwt` and `.env` | — |
| Trust documents | `public/trust-source/signed/trusted-entities.json`, `status-list.jwt` | — |
| Public authorities | `public/trust-source/<role>/ca.pem`, `revocation-list.pem` | — |

`trusted-entities.json` contains compact JWS. The verifier environment file defines `VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE`. The signer certificate is also published at `public/certificates/trust-list-signer/trust_source_cert.pem`.

For the existing Compose consumers, use [compose.override.yaml](examples/compose.override.yaml):

```bash
export PKI_BUNDLE=/absolute/path/to/reported/generation
export PKI_UID="$(id -u)" PKI_GID="$(id -g)"
cd /path/to/wallet-ecosystem
podman compose -f docker-compose.yaml -f /path/to/wallet-pki-tool/examples/compose.override.yaml up -d --force-recreate
```

The Podman override requires Compose support for `!override`. It preserves static trust-source assets and maps the host user so consumers can read owner-only keystores. Recreate consumers when switching generations. Local Traefik/mkcert TLS stays with its existing tooling.

Other deployments consume the same fixed artifact layout. Publish the generated public files through the existing trust-source deployment and deliver keystores through the existing secret-management workflow. Retain private state between runs.

## Migration

The generic schema version 1 and its `plan`/`apply` commands are replaced by named wallet-role operations. Translate environment values into the role sections in the examples. Profiles, arbitrary references, exports, aliases, and filenames are supplied by the implementation.

When migrating schema version 1, use fresh state/output roots for schema version 2. Import existing CA certificate/key/CRL files explicitly to retain trust anchors. Application keystores are not imported automatically: initial role provisioning creates new application keys and requires a coordinated consumer rollout. Keep the previous deployment until the new bundle passes consumer acceptance tests.

Existing schema version 2 configuration and state remain supported. Invoke operations directly, without a deployment-name prefix. Legacy deployment-mode metadata in manifests is ignored.

## Development

```bash
just lint-fix
just verify
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for the module interfaces and tests.
