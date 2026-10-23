# Wallet PKI Tool

[![License](https://img.shields.io/badge/License-CC0_1.0-blue.svg)](LICENSES/CC0-1.0.txt)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/diggsweden/wallet-pki-tool/badge)](https://securityscorecards.dev/viewer/?uri=github.com/diggsweden/wallet-pki-tool)

Generates certificates, keystores and signed trust documents for the Digg wallet development ecosystem.

The status list starts with all entries valid; the tool does not manage revocations.

## Getting started

Requires Java 25 and Maven.

Copy [examples/ecosystem.yaml](examples/ecosystem.yaml) and adjust the participant details and output paths. Set the five password environment variables listed in the file, then run:

```bash
mvn package
java -jar target/wallet-pki-tool.jar init-authorities -c examples/ecosystem.yaml
java -jar target/wallet-pki-tool.jar generate -c examples/ecosystem.yaml
```

`init-authorities` creates the five local certificate authorities and publishes their certificates and CRLs. Running it again reuses the existing authorities. It does not need the keystore passwords.

`generate` creates new participant keys, certificates and signed documents using those authorities. It replaces the selected output files. It fails if the authorities have not been initialized.

## Configuration

The example has settings for the PID issuer, wallet provider, verifier and trust source. All sections are required, even when generating only one participant's files.

Each role lists its output filenames. These paths are relative to `outputDirectory`; all other paths are relative to the directory where you run the command.

Passwords can come from an environment variable:

```yaml
keystorePassword:
  env: PID_ISSUER_KEYSTORE_PASSWORD
```

Or a file:

```yaml
keystorePassword:
  file: /run/secrets/pid-issuer-password
```

Use one source per password. The tool does not load `.env` files itself.

## Generate selected files

With no targets, `generate` creates everything. To update selected files:

```bash
java -jar target/wallet-pki-tool.jar generate -c examples/ecosystem.yaml pid-issuer
java -jar target/wallet-pki-tool.jar generate -c examples/ecosystem.yaml verifier-access verifier-registration
java -jar target/wallet-pki-tool.jar generate -c examples/ecosystem.yaml lote status-list
```

| Target | Generates |
| :--- | :--- |
| `pid-issuer` | Signing and encryption keys in one keystore, plus issuer registration JWT and JSON |
| `wallet-provider` | Wallet attestation signing keystore |
| `verifier-access` | Relying-party access keystore |
| `verifier-registration` | Registration signing keystore, JWT and environment file |
| `trust-source` | Trust-list signing keystore and certificate, LoTE and status list |
| `lote` | LoTE using the existing trust-list signer |
| `status-list` | Status list using the existing trust-list signer |

Only the selected targets need passwords. `lote` and `status-list` use the trust-source password and require an existing signer; run `trust-source` first to create one.

## Output

The example keeps private CA keys in `.wallet-pki/` and writes service files under `config/`:

```text
config/
  certificates/     Participant keystores and verifier registration files
  pid-issuer/      Issuer registration files
  trust-source/    Public CA certificates, CRLs and signed trust documents
```

Keep `.wallet-pki/` private and preserve it between runs. Losing it means losing the CA keys.

The LoTE trusts the four participant CAs. Its file is named `trusted-entities.json` for the consuming service, but contains a signed compact JWS. The status list is also signed by the dedicated trust-source certificate.

## Container

Mount the workspace and pass passwords through an environment file:

```bash
podman run --rm --userns=keep-id \
  -v "$PWD":/workspace:z -w /workspace --env-file .env \
  ghcr.io/diggsweden/wallet-pki-tool:latest \
  init-authorities -c examples/ecosystem.yaml
```

Run the same command with `generate` in place of `init-authorities` to generate the service files.

## Development

```bash
just lint-fix
just verify
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for tool setup.
