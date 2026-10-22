// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.nio.file.Path;
import java.util.Map;
import se.digg.wallet.pki.domain.WalletRole;

/** The immutable generation to deploy and the operations performed for each wallet role. */
public record ProvisioningReport(String environment, String generation, Path bundle,
    Map<WalletRole, String> roles) {
  public ProvisioningReport {
    roles = Map.copyOf(roles);
  }
}
