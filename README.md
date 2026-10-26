# Wallet PKI Tool

[![License](https://img.shields.io/badge/License-CC0_1.0-blue.svg)](LICENSES/CC0-1.0.txt)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/diggsweden/wallet-pki-tool/badge)](https://securityscorecards.dev/viewer/?uri=github.com/diggsweden/wallet-pki-tool)

Generates certificates, keystores and signed trust documents for the Digg wallet development ecosystem.

## Getting started

Requires Java 25 and Maven. Copy [examples/ecosystem.yaml](examples/ecosystem.yaml), adjust participant details and output paths, and set the five password environment variables named in the file.

```bash
mvn package
java -jar target/wallet-pki-tool.jar authorities init -c examples/ecosystem.yaml
java -jar target/wallet-pki-tool.jar ecosystem generate -c examples/ecosystem.yaml
```

Authority initialization is a separate operation. It creates missing roots, reuses complete existing material, and refuses to replace incomplete roots. It needs no keystore passwords. Participant generation requires initialized authorities and creates new keys on every run, replacing the selected output files.

Use `--help` at any level to see the available operations and their prerequisites. `-c`/`--config` can appear before or after the command path. Omitting an operation never generates files.

## Commands and contracts

| Command | Creates or replaces | Required inputs |
| :--- | :--- | :--- |
| `authorities init [ROLE...]` | Missing CAs; selected public CA certificates and CRLs | Shared settings and selected `authorities` common names; no participant configuration or passwords. Defaults to all five authorities. |
| `pid-issuer generate` | Three new keys in one keystore; issuer registration JWT/JSON | `pidIssuer`, its authority and password |
| `wallet-attestation-issuer generate` | New wallet attestation key and keystore | `walletAttestationIssuer`, its authority and password |
| `verifier access generate` | New relying-party access key and keystore | `verifier.access`, its authority and password |
| `verifier registration generate` | New registration key, keystore, JWT and environment file | `verifier.registration`, its authority and password |
| `trust-source generate` | New signer key, keystore and public certificate; LoTE and development status-list fixture | `trustSource.signer` and `lote`; trust-source authority/password and configured public LoTE CAs |
| `trust-source lote generate` | Only the LoTE, retaining the signer | `trustSource.signer` and `lote`; existing signer keystore/password, public trust-source CA and configured public LoTE CAs |
| `ecosystem generate` | All five participant artifact sets and their documents | Complete role configuration, all five authorities and passwords |

Authority names are `pid-issuer`, `wallet-attestation-issuer`, `verifier-access`, `verifier-registration`, and `trust-source`.

Their certificate common names are configured separately under `authorities`. Each operation requires settings only for the local CAs it uses; initializing all five requires all five entries.

Each participant command reads only its required secrets and authorities and leaves unrelated artifacts unchanged. LoTE-only generation needs no CA private keys. Replacing the trust signer always rebuilds its documents so they match the new signer. The LoTE contains the configured CA certificates, so regenerating participant leaves does not require a new LoTE.

The bulk command checks all configuration, passwords, authorities and trust anchors before writing. Output files are then written directly, as in the individual flows; a filesystem or later generation failure can leave partial updates.

## Generate one participant

[examples/wallet-attestation-issuer.yaml](examples/wallet-attestation-issuer.yaml) contains only shared settings and the wallet-attestation-issuer role:

```bash
java -jar target/wallet-pki-tool.jar authorities init wallet-attestation-issuer -c examples/wallet-attestation-issuer.yaml
java -jar target/wallet-pki-tool.jar wallet-attestation-issuer generate -c examples/wallet-attestation-issuer.yaml
```

Other roles can be configured independently in the same way. A verifier can have only `access` or only `registration`. LoTE-only generation requires LoTE settings and the signer keystore/password reference; `signer.commonName` and `certificateFile` are needed only when generating a new signer. Supplied sections are validated even if a command does not use them.

To rebuild the LoTE without replacing the signer:

```bash
java -jar target/wallet-pki-tool.jar trust-source lote generate -c examples/ecosystem.yaml
```

The LoTE sequence number remains configurable; increment it in YAML when publishing an updated list.

### Configure LoTE authorities

Each type under `trustSource.lote.trustedAuthorities` is a list. An entry uses that type's current local CA unless `certificateFile` overrides it with a public PEM CA certificate:

```yaml
trustedAuthorities:
  pidIssuer:
    - entityName: Local PID Provider
      serviceName: PID Issuance
      informationUrl: http://localhost
      streetAddress: Local
    - entityName: Previous PID Provider
      serviceName: Previous PID Issuance
      informationUrl: http://localhost
      streetAddress: Local
      certificateFile: ./trust-anchors/previous-pid-ca.pem
```

Use multiple entries for CA rotation overlap or external CAs. `certificateFile` is an input path relative to the working directory, or an absolute path; it is independent of `outputDirectory`. File overrides need no corresponding local CA or private key and are read without copying or changing the input file.

The supported types are `pidIssuer`, `walletAttestationIssuer`, `verifierAccess`, and `verifierRegistration`. Omitted types and empty lists contribute no entries and require no local CA. The containing type determines the service type, regardless of the certificate's subject. This also allows intentionally incomplete trust lists or CAs assigned to another type for negative testing. Missing files, malformed certificates and certificates without CA basic constraints are rejected before generation writes outputs.

When migrating a single-entry configuration, turn each type's metadata object into a list by adding `-` before its first field and indenting the remaining fields.

## Configuration

Schema version `1` keeps CA common names and role output filenames in YAML. Shared `organization`, `authorities`, `stateDirectory`, `outputDirectory`, and `caDistribution` settings are required:

```yaml
authorities:
  pidIssuer:
    commonName: DIGG Wallet PID Issuer CA
  walletAttestationIssuer:
    commonName: DIGG Wallet Attestation Issuer CA
  verifierAccess:
    commonName: DIGG Wallet Verifier Access Certificate CA
  verifierRegistration:
    commonName: DIGG Wallet Verifier Registration Certificate CA
  trustSource:
    commonName: DIGG Wallet Trust Source CA
```

Authority common names have no built-in defaults. The CA organization and country come from `organization`. Existing CA certificates must match these configured subjects: changing a common name or organization requires an explicit CA migration, and the tool refuses to replace existing material automatically. Keep the names above when migrating a configuration that uses the previous hardcoded subjects. Role identifiers and storage directories remain fixed.

```yaml
caDistribution:
  baseUrl: http://trust-source
  directory: trust-source
  rootCrlFile: trust-source/revocation-list.pem
```

`baseUrl` supplies the URLs embedded in certificates for retrieving CA certificates and CRLs. `directory` and `rootCrlFile` are output paths for public CA material to be served by a web server such as nginx. Artifact paths are relative to `outputDirectory`; other filesystem paths are relative to the directory where you run the command.

Passwords select exactly one environment variable or file:

```yaml
keystorePassword:
  env: WALLET_ATTESTATION_ISSUER_KEYSTORE_PASSWORD
```

```yaml
keystorePassword:
  file: /run/secrets/wallet-attestation-issuer-password
```

The tool does not load `.env` files itself.

### Migrating the wallet generation role

The `wallet-attestation-issuer` command and `walletAttestationIssuer` YAML sections
replace `wallet-provider` and `walletProvider`. Update the authority directory,
output path and password reference when migrating a configuration. The generated
keystore alias is `wallet_attestation_issuer`. Existing CA subjects must still
match the configured common name; the command does not migrate or replace roots.

A legacy wallet-provider service can retain its existing identity during the
migration. Include its public CA as an additional `certificateFile` entry under
`trustSource.lote.trustedAuthorities.walletAttestationIssuer`; both entries use
the standard wallet issuance service type. The generator does not renew that
legacy identity.

## Output

The examples keep private CA keys in `.wallet-pki/` and write service files under `config/`:

```text
config/
  certificates/   Participant keystores and verifier registration files
  pid-issuer/     Issuer registration files
  trust-source/   Public CA certificates, CRLs and signed trust documents
```

Keep `.wallet-pki/` private and preserve it between runs. Losing it means losing the CA keys.

The LoTE file is named `trusted-entities.json` for the consuming service, but contains a signed compact JWS.

On POSIX filesystems, public artifacts use `0644` permissions for container
consumers. Newly created CA private keys retain owner-only permissions.

`trust-source generate` and `ecosystem generate` also create a signed development fixture with 8,192 valid status entries at `<caDistribution.directory>/signed/status-list.jwt`, using `<caDistribution.baseUrl>/signed/status-list.jwt` as its URL and the LoTE validity period; there are no status-list commands or settings, and revocation management is out of scope.

## Container

Mount the workspace and pass passwords through an environment file:

```bash
podman run --rm --userns=keep-id \
  -v "$PWD":/workspace:z -w /workspace --env-file .env \
  ghcr.io/diggsweden/wallet-pki-tool:latest \
  authorities init -c examples/ecosystem.yaml
```

Run the same command with `ecosystem generate` in place of `authorities init` to generate all service files, or select an individual command path.

## Development

```bash
just lint-fix
just verify
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for tool setup.
