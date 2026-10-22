// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import se.digg.wallet.pki.config.PkiConfigurationException;

/** The CLI exposes ecosystem operations, never arbitrary configuration IDs. */
public enum GenerationTarget {
  PID_ISSUER("pid-issuer"), WALLET_PROVIDER("wallet-provider"), VERIFIER_ACCESS("verifier-access"),
  VERIFIER_REGISTRATION("verifier-registration"), TRUST_SOURCE("trust-source"), LOTE("lote"),
  STATUS_LIST("status-list");

  private final String argument;

  GenerationTarget(String argument) {
    this.argument = argument;
  }

  public static EnumSet<GenerationTarget> select(List<String> arguments) {
    if (arguments == null || arguments.isEmpty())
      return EnumSet.allOf(GenerationTarget.class);
    EnumSet<GenerationTarget> selected = EnumSet.noneOf(GenerationTarget.class);
    for (String argument : arguments) {
      selected
          .add(Arrays.stream(values()).filter(value -> value.argument.equals(argument)).findFirst()
              .orElseThrow(
                  () -> new PkiConfigurationException("Unknown generation target: " + argument)));
    }
    if (selected.contains(TRUST_SOURCE)) {
      selected.add(LOTE);
      selected.add(STATUS_LIST);
    }
    return selected;
  }

  @Override
  public String toString() {
    return argument;
  }
}
