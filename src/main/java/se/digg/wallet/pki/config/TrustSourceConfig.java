// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.Checks;

/** LoTE and status lists always use a dedicated leaf under the trust-source CA. */
public record TrustSourceConfig(Signer signer,
    String publicationBaseUrl, String publicationDirectory, String rootCrlFile,
    LoteConfig lote, StatusList statusList) {
  public TrustSourceConfig {
    Checks.required(signer, "trustSource.signer");
    Checks.httpUrl(publicationBaseUrl, "trustSource.publicationBaseUrl");
    Checks.relativePath(publicationDirectory, "trustSource.publicationDirectory");
    Checks.relativePath(rootCrlFile, "trustSource.rootCrlFile");
    Checks.required(lote, "trustSource.lote");
    Checks.required(statusList, "trustSource.statusList");
  }

  public record Signer(String keystoreFile, String certificateFile,
      String commonName, PasswordSource keystorePassword) {
    public Signer {
      Checks.relativePath(keystoreFile, "trustSource.signer.keystoreFile");
      Checks.relativePath(certificateFile, "trustSource.signer.certificateFile");
      Checks.text(commonName, "trustSource.signer.commonName");
      Checks.required(keystorePassword, "trustSource.signer.keystorePassword");
    }
  }
  public record StatusList(String outputFile, String url, int validityDays) {
    public StatusList {
      Checks.relativePath(outputFile, "trustSource.statusList.outputFile");
      Checks.httpUrl(url, "trustSource.statusList.url");
      Checks.positive(validityDays, "trustSource.statusList.validityDays");
    }
  }
}
