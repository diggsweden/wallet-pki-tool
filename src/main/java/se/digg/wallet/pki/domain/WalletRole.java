// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.domain;

import java.util.EnumSet;
import java.util.List;

/** The five supported participant flows and their fixed consumer names. */
public enum WalletRole {
  PID_ISSUER("pid-issuer", "pid_issuer"),
  WALLET_PROVIDER("wallet-provider", "wallet_provider"),
  VERIFIER_ACCESS("verifier-access", "verifier_access_certificate"),
  VERIFIER_REGISTRATION("verifier-registration", "registration"),
  TRUST_SOURCE("trust-source", "trust_source");

  private final String argument;
  private final String alias;

  WalletRole(String argument, String alias) {
    this.argument = argument;
    this.alias = alias;
  }

  public String argument() {
    return argument;
  }

  public String alias() {
    return alias;
  }

  public String directory() {
    return switch (this) {
      case VERIFIER_ACCESS -> "verifier-access-certificate";
      case VERIFIER_REGISTRATION -> "verifier-registration-certificate";
      default -> argument;
    };
  }

  public static EnumSet<WalletRole> select(List<String> arguments, EnumSet<WalletRole> configured) {
    if (arguments.isEmpty()) {
      return EnumSet.copyOf(configured);
    }
    EnumSet<WalletRole> result = EnumSet.noneOf(WalletRole.class);
    for (String argument : arguments) {
      WalletRole role = java.util.Arrays.stream(values()).filter(r -> r.argument.equals(argument))
          .findFirst()
          .orElseThrow(() -> new IllegalArgumentException("Unknown wallet role: " + argument));
      if (!configured.contains(role)) {
        throw new IllegalArgumentException("Role is not configured: " + argument);
      }
      result.add(role);
    }
    return result;
  }
}
