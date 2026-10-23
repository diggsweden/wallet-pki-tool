# Development Guide

## Prerequisites

* [mise](https://mise.jdx.dev/)
* [just](https://github.com/casey/just)
* Java 25 & Maven 3.9+

## Commands

* `just install`: Install tools and dev dependencies.
* `just verify`: Run all linters, formatting checks, and security scans.
* `just test`: Run Maven tests.
* `just lint-fix`: Format Java and other files.

## Application operations

`WalletPkiCli` maps role-first command paths to the named operations in `RoleProvisioner`. The existing participant flows own their certificate recipes, aliases and output files. `WalletServicesPkiGenerator` generates PKI material for the PID issuer, wallet provider, verifier and trust source, preflighting all five roles before invoking the flows. `AuthorityProvisioner` initializes only the selected roots without resolving keystore passwords.

Shared publication settings live in `PublicationConfig`. Role sections may be omitted; each application operation checks its own required sections before resolving secrets or changing outputs. Existing full configurations with publication settings under `trustSource` remain supported.

`WalletPkiCliComponentTest` exercises real CLI parsing, YAML, keys, certificates, PKCS12 stores, signed documents and temporary files. It checks partial configurations, selective secret/authority access, command isolation, prerequisite failures and trust-signer dependencies. No running wallet services are needed.
