// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.Checks;

/** Shared public CA distribution settings, independent of trust-document generation. */
public record CaDistributionConfig(String baseUrl, String directory, String rootCrlFile) {
  public CaDistributionConfig {
    Checks.httpUrl(baseUrl, "caDistribution.baseUrl");
    Checks.relativePath(directory, "caDistribution.directory");
    Checks.relativePath(rootCrlFile, "caDistribution.rootCrlFile");
  }
}
