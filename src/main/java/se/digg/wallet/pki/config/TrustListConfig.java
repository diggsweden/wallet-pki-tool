// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Configuration model for a trust list (such as LoTE or OAuth Status List). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record TrustListConfig(
    String id,
    String type,
    String signerAuthority,
    String outputFile) {

  /**
   * Compact constructor enforcing model invariants and default type.
   */
  public TrustListConfig {
    if (id == null || id.isBlank()) {
      throw new IllegalArgumentException("Trust list 'id' is required and cannot be blank");
    }
    if (signerAuthority == null || signerAuthority.isBlank()) {
      throw new IllegalArgumentException(
          "Trust list 'signerAuthority' is required for: %s".formatted(id));
    }
    if (outputFile == null || outputFile.isBlank()) {
      throw new IllegalArgumentException(
          "Trust list 'outputFile' is required for: %s".formatted(id));
    }
    if (type == null || type.isBlank()) {
      type = "etsi-119-602-lote";
    }
  }
}
