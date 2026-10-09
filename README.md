# Wallet PKI Tool (`wallet-pki-tool`)

[![License](https://img.shields.io/badge/License-CC0_1.0-blue.svg)](LICENSES/CC0-1.0.txt)

`wallet-pki-tool` is a dedicated command-line interface (CLI) for automating certificate, keystore (`.p12`), and List of Trusted Entities (LoTE) generation across the European Digital Identity (EUDI) Wallet ecosystem.

It replaces fragile and complex bash scripts with a strongly typed, unit-tested Java engine driven by declarative YAML configurations.

---

## Key Features

* **Declarative EUDI Model:** Driven by clean, human-readable YAML configurations without cryptic OpenSSL syntax.
* **Standard-Compliant:** Implements EUDI certificate profiles ([ETSI TS 119 411-8](https://www.etsi.org/deliver/etsi_ts/119400_119499/11941108/01.01.01_60/ts_11941108v010101p.pdf), [ETSI TS 119 475](https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf)) and LoTE trust lists ([ETSI TS 119 602](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf)).
* **Secure Secret Management:** Passwords and private keys are resolved strictly from environment variables or secret files (no passwords exposed in CLI flags or process tables).
* **Selective Target Generation:** Allows rotating or regenerating specific certificates without resetting the entire ecosystem.
* **Automated Licensing:** Produces REUSE-compliant `.license` files for all generated artifacts.

---

## Quick Start

### 1. Build

```bash
# Build the executable fat-JAR
mvn clean package
```

### 2. Run CLI

Generated PKCS#12 keystores (`.p12`) require encryption passwords to protect their private keys. The YAML configuration specifies which environment variables contain these passwords (via the `passwordEnv` property).

Before generating, ensure the corresponding environment variables are set in your shell (or loaded from a `.env` file):

```bash
# Display help and available commands
java -jar target/wallet-pki-tool.jar --help

# Set the keystore passwords required by ecosystem.yaml (or source your .env file)
export VERIFIER_ACCESS_CERTIFICATE_KEYSTORE_PASSWORD="my-password"
export PID_ISSUER_KEYSTORE_PASSWORD="my-password"
export WALLET_PROVIDER_KEYSTORE_PASSWORD="my-password"

# Generate all certificates, keystores, and trust lists
java -jar target/wallet-pki-tool.jar generate --config ./config/certificates/ecosystem.yaml
```

### 3. Selective Target Rotation

You can specify one or more target IDs to selectively regenerate only those artifacts:

```bash
# Regenerate only the verifier access certificate
java -jar target/wallet-pki-tool.jar generate \
  --config ./config/certificates/ecosystem.yaml \
  verifier-access-certificate

# Regenerate multiple specific targets
java -jar target/wallet-pki-tool.jar generate \
  --config ./config/certificates/ecosystem.yaml \
  pid-issuer wallet-provider
```

---

## Running with Docker / Podman

`wallet-pki-tool` can be executed as a container without installing Java locally:

```bash
podman run --rm \
  -v "$PWD":/workspace:z \
  -w /workspace \
  -e VERIFIER_ACCESS_CERTIFICATE_KEYSTORE_PASSWORD \
  -e PID_ISSUER_KEYSTORE_PASSWORD \
  -e WALLET_PROVIDER_KEYSTORE_PASSWORD \
  ghcr.io/diggsweden/wallet-pki-tool:latest \
  generate --config ./config/certificates/ecosystem.yaml
```

---

## Configuration Reference (YAML)

Configurations define **what** actors exist and **how** they relate to Certificate Authorities. The tool handles standard X.509 extensions, `qcStatements`, KeyUsages, and PKCS#12 formatting automatically.

### Example: `ecosystem.yaml`

```yaml
environment: local
outputDir: ./config/certificates

# ---------------------------------------------------------------------------
# 1. Certificate Authorities (CAs)
# ---------------------------------------------------------------------------
authorities:
  - id: verifier-access-ca
    commonName: "DIGG Wallet Verifier Access CA"
  - id: pid-issuer-ca
    commonName: "DIGG Wallet PID Issuer CA"
  - id: wallet-provider-ca
    commonName: "DIGG Wallet Provider CA"
  - id: trust-source-ca
    commonName: "DIGG Wallet Trust Source CA"

# ---------------------------------------------------------------------------
# 2. Service Certificates & Keystores (.p12)
# ---------------------------------------------------------------------------
certificates:
  # Relying Party Access Certificate (WRPAC - ETSI TS 119 411-8)
  - id: verifier-access-certificate
    type: relying-party-access
    ca: verifier-access-ca
    keystore: ./verifier-access-certificate/verifier-access-certificate.p12
    passwordEnv: VERIFIER_ACCESS_CERTIFICATE_KEYSTORE_PASSWORD
    sans:
      - "localhost"
      - "verifier-backend"
    tradeName: "DIGG Verifier"
    country: "SE"
    organizationIdentifier: "VATSE-12345678"

  # PID Issuer Service Certificate & Keystore
  - id: pid-issuer
    type: pid-issuer-service
    ca: pid-issuer-ca
    keystore: ./issuer/pid_issuer.p12
    passwordEnv: PID_ISSUER_KEYSTORE_PASSWORD
    sans:
      - "localhost"
      - "pid-issuer"

  # Wallet Provider Service Certificate & Keystore
  - id: wallet-provider
    type: wallet-provider-service
    ca: wallet-provider-ca
    keystore: ./wallet-provider/wallet_provider.p12
    passwordEnv: WALLET_PROVIDER_KEYSTORE_PASSWORD
    sans:
      - "localhost"
      - "wallet-provider"

# ---------------------------------------------------------------------------
# 3. Trust Lists & Signed Tokens (LoTE - ETSI TS 119 602 / OAuth Status List)
# ---------------------------------------------------------------------------
trustLists:
  - id: lote
    type: etsi-119-602-lote
    signerAuthority: trust-source-ca
    outputFile: ./trust-source/signed/trusted-entities.json
    entities:
      - wallet-provider
      - pid-issuer

  - id: status-list
    type: oauth-status-list
    signerAuthority: trust-source-ca
    outputFile: ./trust-source/signed/status-list.jwt
    url: "https://trust.example.se/signed/status-list.jwt"
```

---

## Configuration Fields

### Root Properties

| Property | Type | Description |
| :--- | :--- | :--- |
| `environment` | `String` | Optional environment identifier (e.g. `local`, `sandbox`, `prod`). |
| `outputDir` | `String` | Target base directory where generated certificates and keystores are written. |
| `authorities` | `List` | List of Certificate Authority configurations. |
| `certificates` | `List` | List of service certificates and PKCS#12 keystores to generate. |
| `trustLists` | `List` | List of trust lists (such as LoTE) and tokens to compile and sign. |

### `authorities` Properties

| Property | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `id` | `String` | **Yes** | Unique identifier for the CA referenced by service certificates. |
| `commonName` | `String` | **Yes** | Subject Common Name (CN) for the CA certificate. |
| `keyType` | `String` | No | Key algorithm and curve (defaults to `EC_P256`). |
| `keyFile` | `String` | No | Optional path to existing private key file (for Kubernetes/OpenShift Sealed Secrets). |
| `certFile` | `String` | No | Optional path to existing CA certificate. |

### `certificates` Properties

| Property | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `id` | `String` | **Yes** | Unique identifier for the certificate. |
| `type` | `String` | No | Profile type (`relying-party-access`, `pid-issuer-service`, `wallet-provider-service`, `trust-source-signer`, `encryption`). |
| `ca` | `String` | **Yes** | ID of the authority used to issue this certificate. |
| `keystore` | `String` | **Yes** | Relative path where the `.p12` keystore should be written. |
| `passwordEnv` | `String` | Conditional | Environment variable name containing the keystore password. |
| `passwordFile` | `String` | Conditional | File path containing the keystore password (alternative to `passwordEnv`). |
| `sans` | `List<String>` | No | Subject Alternative Names (DNS hostnames, IP addresses, or URIs). |
| `tradeName` | `String` | No | Trade name for Relying Party certificates. |
| `country` | `String` | No | Two-letter country code (default: `SE`). |
| `organizationIdentifier` | `String` | No | Legal entity identifier (e.g. `VATSE-...` or `NTRSE-...`). |

### `trustLists` Properties

| Property | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `id` | `String` | **Yes** | Unique identifier for the trust list. |
| `type` | `String` | No | Trust list format (`etsi-119-602-lote` or `oauth-status-list`, default: `etsi-119-602-lote`). |
| `signerAuthority` | `String` | **Yes** | Authority ID used to sign the trust list. |
| `outputFile` | `String` | **Yes** | Output destination path for the signed JSON/JWT. |
| `url` | `String` | No | Optional issuer URL (`iss`/`sub`) for OAuth Status List JWTs. |
| `entities` | `List<String>` | No | Optional list of entity/certificate IDs to include in the LoTE. Defaults to auto-discovering wallet-provider and pid-issuer. |

---

## Secret Management

To prevent sensitive passwords and private keys from leaking in shell history or process tables (`ps aux`), `wallet-pki-tool` supports two secure resolution mechanisms:

1. **Environment Variables (`passwordEnv`):**  
   Reads the password from the named environment variable at runtime.
2. **Secret Files (`passwordFile`):**  
   Reads the password from a mounted secret file (ideal for OpenShift/Kubernetes Sealed Secrets).

---

## Development

The project uses [just](https://github.com/casey/just) and [mise](https://mise.jdx.dev/) for local workflow automation:

```bash
# Bootstrap tools and dependencies
just install

# Run linters, formatting, and security audits
just verify

# Run unit tests
just test

# Auto-fix formatting issues
just lint-fix
```
