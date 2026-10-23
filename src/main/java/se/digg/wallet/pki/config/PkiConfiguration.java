// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.util.EnumSet;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.WalletRole;

/** Environment values for the wallet roles; profiles, aliases and exports are fixed in code. */
public record PkiConfiguration(String authorityDirectory, String outputDirectory,
    String publicationBaseUrl, Organization organization,
    PidIssuerConfig pidIssuer, WalletProviderConfig walletProvider, VerifierConfig verifier,
    TrustSourceConfig trustSource) {
  public PkiConfiguration {
    authorityDirectory = authorityDirectory == null ? ".wallet-pki/authorities"
        : Checks.text(authorityDirectory, "authorityDirectory");
    outputDirectory =
        outputDirectory == null ? "generated" : Checks.text(outputDirectory, "outputDirectory");
    Checks.httpUrl(publicationBaseUrl, "publicationBaseUrl");
    Checks.required(organization, "organization");
    if (pidIssuer == null && walletProvider == null && verifier == null && trustSource == null) {
      throw new IllegalArgumentException("Configure at least one wallet role");
    }
  }

  public EnumSet<WalletRole> configuredRoles() {
    var roles = EnumSet.noneOf(WalletRole.class);
    if (pidIssuer != null) {
      roles.add(WalletRole.PID_ISSUER);
    }
    if (walletProvider != null) {
      roles.add(WalletRole.WALLET_PROVIDER);
    }
    if (verifier != null && verifier.access() != null) {
      roles.add(WalletRole.VERIFIER_ACCESS);
    }
    if (verifier != null && verifier.registration() != null) {
      roles.add(WalletRole.VERIFIER_REGISTRATION);
    }
    if (trustSource != null) {
      roles.add(WalletRole.TRUST_SOURCE);
    }
    return roles;
  }

  public AuthorityConfig authority(WalletRole role) {
    return switch (role) {
      case PID_ISSUER -> pidIssuer.authority();
      case WALLET_PROVIDER -> walletProvider.authority();
      case VERIFIER_ACCESS -> verifier.access().authority();
      case VERIFIER_REGISTRATION -> verifier.registration().authority();
      case TRUST_SOURCE -> trustSource.authority();
    };
  }

  public PasswordSource password(WalletRole role) {
    return switch (role) {
      case PID_ISSUER -> pidIssuer.keystorePassword();
      case WALLET_PROVIDER -> walletProvider.keystorePassword();
      case VERIFIER_ACCESS -> verifier.access().keystorePassword();
      case VERIFIER_REGISTRATION -> verifier.registration().keystorePassword();
      case TRUST_SOURCE -> trustSource.signer().keystorePassword();
    };
  }
}
