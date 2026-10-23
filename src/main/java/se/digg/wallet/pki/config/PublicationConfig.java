// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.Checks;

/** Shared certificate publication settings, independent of trust-document generation. */
public record PublicationConfig(String baseUrl, String directory, String rootCrlFile) {
  public PublicationConfig {
    Checks.httpUrl(baseUrl, "publication.baseUrl");
    Checks.relativePath(directory, "publication.directory");
    Checks.relativePath(rootCrlFile, "publication.rootCrlFile");
  }
}
