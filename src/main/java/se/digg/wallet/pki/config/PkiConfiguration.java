// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.nio.file.Path;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.Organization;

/** Shared settings and optional wallet roles; each operation requires its own role inputs. */
public record PkiConfiguration(int schemaVersion, String stateDirectory, String outputDirectory,
    Organization organization, PublicationConfig publication,
    PidIssuerConfig pidIssuer, WalletProviderConfig walletProvider,
    VerifierConfig verifier, TrustSourceConfig trustSource) {
  public PkiConfiguration {
    if (schemaVersion != 1)
      throw new IllegalArgumentException(
          "schemaVersion must be 1; generic authorities/certificates configuration is no longer supported");
    Checks.text(stateDirectory, "stateDirectory");
    Checks.text(outputDirectory, "outputDirectory");
    Checks.required(organization, "organization");
    if (publication == null && trustSource != null) {
      publication = new PublicationConfig(trustSource.publicationBaseUrl(),
          trustSource.publicationDirectory(), trustSource.rootCrlFile());
    } else if (publication != null && trustSource != null
        && (trustSource.publicationBaseUrl() != null
            || trustSource.publicationDirectory() != null || trustSource.rootCrlFile() != null)) {
      throw new IllegalArgumentException(
          "Configure publication settings in publication or trustSource, not both");
    }
    Checks.required(publication, "publication");
    Path state = Path.of(stateDirectory).toAbsolutePath().normalize();
    Path publicDirectory =
        Path.of(outputDirectory).resolve(publication.directory()).toAbsolutePath()
            .normalize();
    if (state.startsWith(publicDirectory) || publicDirectory.startsWith(state))
      throw new IllegalArgumentException(
          "Private state and public trust-source directories must not overlap");
  }
}
