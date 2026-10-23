// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.Checks;

/** Wallet attestation signing material, issued by its own authority. */
public record WalletProviderConfig(AuthorityConfig authority, SigningConfig signing,
    PasswordSource keystorePassword) {
  public WalletProviderConfig {
    Checks.required(authority, "walletProvider.authority");
    Checks.required(signing, "walletProvider.signing");
    Checks.required(keystorePassword, "walletProvider.keystorePassword");
  }
}
