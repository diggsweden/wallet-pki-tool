// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.Checks;

/** A dedicated leaf under the trust-source CA signs the trust documents. */
public record TrustSourceConfig(Signer signer,
    String publicationBaseUrl, String publicationDirectory, String rootCrlFile,
    LoteConfig lote) {
  public TrustSourceConfig {
    if (publicationBaseUrl != null) {
      Checks.httpUrl(publicationBaseUrl, "trustSource.publicationBaseUrl");
    }
    if (publicationDirectory != null) {
      Checks.relativePath(publicationDirectory, "trustSource.publicationDirectory");
    }
    if (rootCrlFile != null) {
      Checks.relativePath(rootCrlFile, "trustSource.rootCrlFile");
    }
  }

  public record Signer(String keystoreFile, String certificateFile,
      String commonName, PasswordSource keystorePassword) {
    public Signer {
      Checks.relativePath(keystoreFile, "trustSource.signer.keystoreFile");
      if (certificateFile != null) {
        Checks.relativePath(certificateFile, "trustSource.signer.certificateFile");
      }
      if (commonName != null) {
        Checks.text(commonName, "trustSource.signer.commonName");
      }
      Checks.required(keystorePassword, "trustSource.signer.keystorePassword");
    }
  }
}
