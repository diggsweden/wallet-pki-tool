// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.util.EnumSet;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.WalletRole;

/** Environment values for the wallet roles; profiles, aliases and exports are fixed in code. */
public record PkiConfiguration(int schemaVersion, String environment, String stateDirectory,
    String outputDirectory, String publicationBaseUrl, Organization organization,
    PidIssuerConfig pidIssuer, WalletProviderConfig walletProvider, VerifierConfig verifier,
    TrustSourceConfig trustSource) {
  public PkiConfiguration {
    if (schemaVersion != 2) {
      throw new IllegalArgumentException(
          "schemaVersion must be 2; migrate legacy configuration to named wallet roles");
    }
    if (environment == null || !environment.matches("[a-z][a-z0-9-]*")) {
      throw new IllegalArgumentException("environment must match [a-z][a-z0-9-]*");
    }
    Checks.text(stateDirectory, "stateDirectory");
    Checks.text(outputDirectory, "outputDirectory");
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

  public Object settings(WalletRole role) {
    return switch (role) {
      case PID_ISSUER -> pidIssuer;
      case WALLET_PROVIDER -> walletProvider;
      case VERIFIER_ACCESS -> verifier.access();
      case VERIFIER_REGISTRATION -> verifier.registration();
      case TRUST_SOURCE -> trustSource;
    };
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
