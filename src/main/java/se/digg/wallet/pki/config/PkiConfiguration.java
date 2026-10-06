// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/** Configuration model representing the root PKI YAML configuration. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record PkiConfiguration(
    String environment,
    String outputDir,
    List<AuthorityConfig> authorities,
    List<CertificateConfig> certificates,
    List<TrustListConfig> trustLists) {

  /**
   * Compact constructor enforcing outputDir invariant and providing default empty lists.
   */
  public PkiConfiguration {
    if (outputDir == null || outputDir.isBlank()) {
      throw new IllegalArgumentException("Field 'outputDir' is required in configuration");
    }
    authorities = authorities != null ? List.copyOf(authorities) : List.of();
    certificates = certificates != null ? List.copyOf(certificates) : List.of();
    trustLists = trustLists != null ? List.copyOf(trustLists) : List.of();
  }
}
