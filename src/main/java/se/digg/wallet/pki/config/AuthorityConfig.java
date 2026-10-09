// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Configuration model for a Certificate Authority (CA). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AuthorityConfig(
    String id,
    String commonName,
    String keyType,
    String keyFile,
    String certFile) {

  /**
   * Compact constructor enforcing model invariants and providing default keyType.
   */
  public AuthorityConfig {
    if (id == null || id.isBlank()) {
      throw new IllegalArgumentException("Authority 'id' is required and cannot be blank");
    }
    if (commonName == null || commonName.isBlank()) {
      throw new IllegalArgumentException(
          "Authority 'commonName' is required for authority: %s".formatted(id));
    }
    if (keyType == null || keyType.isBlank()) {
      keyType = "EC_P256";
    }
    if ((keyFile != null && certFile == null) || (keyFile == null && certFile != null)) {
      throw new IllegalArgumentException(
          "Both 'keyFile' and 'certFile' must be provided when configuring external CA for"
              + " authority: %s"
                  .formatted(id));
    }
  }

  /**
   * Convenience constructor for basic CA configuration.
   *
   * @param id authority identifier
   * @param commonName common name
   */
  public AuthorityConfig(String id, String commonName) {
    this(id, commonName, "EC_P256", null, null);
  }
}
