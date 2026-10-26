// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.nio.file.Path;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.Organization;

/** Shared settings and optional wallet roles; each operation requires its own role inputs. */
public record PkiConfiguration(int schemaVersion, String stateDirectory, String outputDirectory,
    Organization organization, AuthoritiesConfig authorities, CaDistributionConfig caDistribution,
    PidIssuerConfig pidIssuer, WalletAttestationIssuerConfig walletAttestationIssuer,
    VerifierConfig verifier, TrustSourceConfig trustSource) {
  public PkiConfiguration {
    if (schemaVersion != 1) {
      throw new IllegalArgumentException("schemaVersion must be 1");
    }
    Checks.text(stateDirectory, "stateDirectory");
    Checks.text(outputDirectory, "outputDirectory");
    Checks.required(organization, "organization");
    Checks.required(authorities, "authorities");
    if (caDistribution == null && trustSource != null) {
      caDistribution = new CaDistributionConfig(trustSource.publicationBaseUrl(),
          trustSource.publicationDirectory(), trustSource.rootCrlFile());
    } else if (caDistribution != null && trustSource != null
        && (trustSource.publicationBaseUrl() != null
            || trustSource.publicationDirectory() != null || trustSource.rootCrlFile() != null)) {
      throw new IllegalArgumentException(
          "Configure CA distribution settings in caDistribution or trustSource, not both");
    }
    caDistribution = Checks.required(caDistribution, "caDistribution");
    Path state = Path.of(stateDirectory).toAbsolutePath().normalize();
    Path publicDirectory =
        Path.of(outputDirectory).resolve(caDistribution.directory()).toAbsolutePath()
            .normalize();
    if (state.startsWith(publicDirectory) || publicDirectory.startsWith(state)) {
      throw new IllegalArgumentException(
          "Private state and public trust-source directories must not overlap");
    }
  }
}
