// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.Checks;

/** Wallet attestation signing material, issued by its own authority. */
public record WalletAttestationIssuerConfig(String keystoreFile, SigningConfig signing,
    PasswordSource keystorePassword) {
  public WalletAttestationIssuerConfig {
    Checks.relativePath(keystoreFile, "walletAttestationIssuer.keystoreFile");
    Checks.required(signing, "walletAttestationIssuer.signing");
    Checks.required(keystorePassword, "walletAttestationIssuer.keystorePassword");
  }
}
