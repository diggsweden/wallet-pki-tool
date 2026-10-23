// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.nio.file.Path;
import java.util.Set;
import se.digg.wallet.pki.domain.WalletRole;

/** The validated output directory and its generated wallet roles. */
public record GeneratedArtifacts(Path directory, Set<WalletRole> roles) {
  public GeneratedArtifacts {
    roles = Set.copyOf(roles);
  }
}
