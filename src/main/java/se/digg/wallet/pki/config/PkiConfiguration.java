// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.nio.file.Path;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.Organization;

/** Complete configuration for the five wallet ecosystem roles. */
public record PkiConfiguration(int schemaVersion, String stateDirectory, String outputDirectory,
    Organization organization, PidIssuerConfig pidIssuer, WalletProviderConfig walletProvider,
    VerifierConfig verifier, TrustSourceConfig trustSource) {
  public PkiConfiguration {
    if (schemaVersion != 1)
      throw new IllegalArgumentException(
          "schemaVersion must be 1; generic authorities/certificates configuration is no longer supported");
    Checks.text(stateDirectory, "stateDirectory");
    Checks.text(outputDirectory, "outputDirectory");
    Checks.required(organization, "organization");
    Checks.required(pidIssuer, "pidIssuer");
    Checks.required(walletProvider, "walletProvider");
    Checks.required(verifier, "verifier");
    Checks.required(trustSource, "trustSource");
    Path state = Path.of(stateDirectory).toAbsolutePath().normalize();
    Path publication =
        Path.of(outputDirectory).resolve(trustSource.publicationDirectory()).toAbsolutePath()
            .normalize();
    if (state.startsWith(publication) || publication.startsWith(state))
      throw new IllegalArgumentException(
          "Private state and public trust-source directories must not overlap");
  }
}
