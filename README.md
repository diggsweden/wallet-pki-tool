# Wallet PKI Tool

[![License](https://img.shields.io/badge/License-CC0_1.0-blue.svg)](LICENSES/CC0-1.0.txt)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/diggsweden/wallet-pki-tool/badge)](https://securityscorecards.dev/viewer/?uri=github.com/diggsweden/wallet-pki-tool)

Generates certificates, keystores and signed trust documents for the Digg wallet development ecosystem.

The status list starts with all entries valid; the tool does not manage revocations.

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
| `authorities init [ROLE...]` | Missing CAs; selected public CA certificates and CRLs | Shared settings; no participant configuration or passwords. Defaults to all five authorities. |
| `pid-issuer generate` | Three new keys in one keystore; issuer registration JWT/JSON | `pidIssuer`, its authority and password |
| `wallet-provider generate` | New wallet attestation key and keystore | `walletProvider`, its authority and password |
| `verifier access generate` | New relying-party access key and keystore | `verifier.access`, its authority and password |
| `verifier registration generate` | New registration key, keystore, JWT and environment file | `verifier.registration`, its authority and password |
| `trust-source generate` | New signer key, keystore and public certificate; both LoTE and status list | `trustSource.signer`, `lote`, `statusList`; trust-source authority/password and four public participant CAs |
| `trust-source lote generate` | Only the LoTE, retaining the signer | `trustSource.signer` and `lote`; existing signer keystore/password and five public CAs |
| `trust-source status-list generate` | Only the status list, retaining the signer | `trustSource.signer` and `statusList`; existing signer keystore/password and public trust-source CA |
| `ecosystem generate` | All five participant artifact sets and their documents | Complete role configuration, all five authorities and passwords |

Authority names are `pid-issuer`, `wallet-provider`, `verifier-access`, `verifier-registration`, and `trust-source`.

Each participant command reads only its required secrets and authorities and leaves unrelated artifacts unchanged. Document-only commands need no CA private keys. Replacing the trust signer always rebuilds both documents so they match the new signer. The LoTE contains the four participant CAs, so regenerating participant leaves does not require a new LoTE.

The bulk command checks all configuration, passwords, authorities and trust anchors before writing. Output files are then written directly, as in the individual flows; a filesystem or later generation failure can leave partial updates.

## Generate one participant

[examples/wallet-provider.yaml](examples/wallet-provider.yaml) contains only shared settings and the wallet-provider role:

```bash
java -jar target/wallet-pki-tool.jar authorities init wallet-provider -c examples/wallet-provider.yaml
java -jar target/wallet-pki-tool.jar wallet-provider generate -c examples/wallet-provider.yaml
```

Other roles can be configured independently in the same way. A verifier can have only `access` or only `registration`. A trust-source document command requires only its document settings and signer keystore/password reference; `signer.commonName` and `certificateFile` are needed only when generating a new signer. Supplied sections are validated even if a command does not use them.

To rebuild documents without replacing the signer:

```bash
java -jar target/wallet-pki-tool.jar trust-source lote generate -c examples/ecosystem.yaml
java -jar target/wallet-pki-tool.jar trust-source status-list generate -c examples/ecosystem.yaml
```

The LoTE sequence number remains configurable; increment it in YAML when publishing an updated list.

## Configuration

Schema version `1` keeps role output filenames in YAML. Shared `organization`, `stateDirectory`, `outputDirectory`, and `publication` settings are required:

```yaml
publication:
  baseUrl: http://trust-source
  directory: trust-source
  rootCrlFile: trust-source/revocation-list.pem
```

`baseUrl` supplies certificate publication URLs. `directory` and `rootCrlFile` are output paths for public CA material. Artifact paths are relative to `outputDirectory`; other filesystem paths are relative to the directory where you run the command.

Passwords select exactly one environment variable or file:

```yaml
keystorePassword:
  env: WALLET_PROVIDER_KEYSTORE_PASSWORD
```

```yaml
keystorePassword:
  file: /run/secrets/wallet-provider-password
```

The tool does not load `.env` files itself.

Existing full role configurations with `publicationBaseUrl`, `publicationDirectory`, and `rootCrlFile` inside `trustSource` remain readable. To use a partial configuration, move those three settings to `publication`, using `baseUrl`, `directory`, and `rootCrlFile`. Do not configure both locations. The former `init-authorities` and `generate [TARGETS...]` commands are replaced by the command paths above; existing state and artifact paths are preserved.

## Output

The examples keep private CA keys in `.wallet-pki/` and write service files under `config/`:

```text
config/
  certificates/   Participant keystores and verifier registration files
  pid-issuer/     Issuer registration files
  trust-source/   Public CA certificates, CRLs and signed trust documents
```

Keep `.wallet-pki/` private and preserve it between runs. Losing it means losing the CA keys.

The LoTE file is named `trusted-entities.json` for the consuming service, but contains a signed compact JWS. The status list is also signed by the dedicated trust-source certificate.

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
