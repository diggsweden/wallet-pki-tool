# Wallet PKI Tool (`wallet-pki-tool`)

[![License](https://img.shields.io/badge/License-CC0_1.0-blue.svg)](LICENSES/CC0-1.0.txt)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/diggsweden/wallet-pki-tool/badge)](https://securityscorecards.dev/viewer/?uri=github.com/diggsweden/wallet-pki-tool)

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

Generated PKCS#12 keystores (`.p12`) require encryption passwords to protect their private keys. The YAML configuration specifies which environment variables contain these passwords (via the `passwordEnv` property). Ensure required passwords are set in the environment or available in a `.env` file before executing generation.

All certificates, keystores, and trust lists can be generated using either of the following two methods:

### Option 1: Running with Container (Recommended)

No local Java installation is required. `wallet-pki-tool` executes directly inside a container using Podman or Docker:

```bash
podman run --rm \
  --userns=keep-id \
  --user "$(id -u):$(id -g)" \
  -v "$PWD":/workspace:z \
  -w /workspace \
  --env-file .env \
  ghcr.io/diggsweden/wallet-pki-tool:latest \
  generate --config ./config/certificates/ecosystem.yaml
```

To build the container image locally:

```bash
podman build -t wallet-pki-tool -f Containerfile .
```

### Option 2: Running with Local Java (Fat-JAR)

Requires Java 25 installed locally:

```bash
# 1. Build the executable fat-JAR
./mvnw clean package

# 2. Display help and available commands
java -jar target/wallet-pki-tool.jar --help

# 3. Export keystore passwords required by ecosystem.yaml (or source .env)
export VERIFIER_ACCESS_CERTIFICATE_KEYSTORE_PASSWORD="my-password"
export VERIFIER_REGISTRATION_CERTIFICATE_KEYSTORE_PASSWORD="my-password"
export PID_ISSUER_KEYSTORE_PASSWORD="my-password"
export WALLET_PROVIDER_KEYSTORE_PASSWORD="my-password"
export TRUST_SOURCE_KEYSTORE_PASSWORD="my-password"

# 4. Generate all certificates, keystores, and trust lists
java -jar target/wallet-pki-tool.jar generate --config ./config/certificates/ecosystem.yaml
```

---

### Selective Target Rotation

Specific target IDs can be specified to selectively regenerate only those artifacts, using either execution method:

```bash
# With container
podman run --rm \
  --userns=keep-id \
  --user "$(id -u):$(id -g)" \
  -v "$PWD":/workspace:z \
  -w /workspace \
  --env-file .env \
  ghcr.io/diggsweden/wallet-pki-tool:latest \
  generate --config ./config/certificates/ecosystem.yaml \
  verifier-access-certificate

# With local Java fat-JAR
java -jar target/wallet-pki-tool.jar generate \
  --config ./config/certificates/ecosystem.yaml \
  verifier-access-certificate
```

Multiple targets can also be combined:

```bash
java -jar target/wallet-pki-tool.jar generate \
  --config ./config/certificates/ecosystem.yaml \
  pid-issuer wallet-provider
```

---

### Output Directory Structure

Both execution methods populate the configured `outputDir` (`./config/certificates`) with the following structure:

```text
config/certificates/
├── ca/
│   ├── verifier-access-ca/       # ca.pem, ca_private_key.pem, revocation-list.pem
│   ├── verifier-registration-certificate/
│   ├── pid-issuer-ca/
│   ├── wallet-provider-ca/
│   └── trust-source-ca/
├── verifier-access-certificate/
│   └── verifier-access-certificate.p12
├── verifier-registration-certificate/
│   ├── verifier-registration-certificate.p12
│   ├── registration_certificate.jwt
│   └── registration_certificate.env
├── issuer/
│   └── pid_issuer.p12            # Merged service & encryption keys
├── wallet-provider/
│   └── wallet_provider.p12
├── trust-source/
│   └── signed/
│       ├── trusted-entities.json # Signed LoTE document (ETSI TS 119 602)
│       └── status-list.jwt       # OAuth Status List JWT
└── trusted_issuers.p12           # Verifier truststore
```

---

## Verifying Generated Artifacts

Once generated, you can inspect and verify the contents of the keystores, certificates, and trust lists using standard tools:

### 1. Inspect Keystores (`.p12`) with Java `keytool`

View certificate aliases, key algorithms (EC P-256), and certificate chain hierarchy:

```bash
keytool -list -v \
  -keystore ./config/certificates/issuer/pid_issuer.p12 \
  -storepass "$PID_ISSUER_KEYSTORE_PASSWORD"
```

### 2. Inspect Keystores (`.p12`) with `openssl`

Display human-readable certificate details (Subject, Issuer, SANs, and QCStatements):

```bash
openssl pkcs12 \
  -in ./config/certificates/issuer/pid_issuer.p12 \
  -nokeys \
  -passin env:PID_ISSUER_KEYSTORE_PASSWORD | openssl x509 -text -noout
```

### 3. Inspect Root CA Certificates (`.pem`)

Verify CA Distinguished Name (DN), validity, and basic constraints:

```bash
openssl x509 \
  -in ./config/certificates/ca/pid-issuer-ca/ca.pem \
  -text -noout
```

### 4. Inspect Signed Trust List (LoTE JSON)

Format and inspect the trusted entities in the LoTE document:

```bash
cat ./config/certificates/trust-source/signed/trusted-entities.json | jq .
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
  - id: verifier-registration-certificate
    commonName: "DIGG Wallet Verifier Registration Certificate CA"
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

  # Relying Party Registration Certificate (WRPRC - ETSI TS 119 475)
  - id: verifier-registration-certificate
    type: relying-party-registration
    ca: verifier-registration-certificate
    keystore: ./verifier-registration-certificate/verifier-registration-certificate.p12
    passwordEnv: VERIFIER_REGISTRATION_CERTIFICATE_KEYSTORE_PASSWORD
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
      - verifier-access-certificate
      - verifier-registration-certificate

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
| `type` | `String` | No | Profile type (`relying-party-access`, `relying-party-registration`, `pid-issuer-service`, `wallet-provider-service`, `trust-source-signer`, `encryption`). |
| `ca` | `String` | **Yes** | ID of the authority used to issue this certificate. |
| `keystore` | `String` | **Yes** | Relative path where the `.p12` keystore should be written. |
| `alias` | `String` | No | Custom alias for the private key and cert in the `.p12` store (defaults to `id` with underscores). |
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
