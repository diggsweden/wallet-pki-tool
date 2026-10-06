// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/** Configuration model for a service certificate. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CertificateConfig(
    String id,
    String type,
    String ca,
    String keystore,
    String passwordEnv,
    String passwordFile,
    List<String> sans,
    String tradeName,
    String country,
    String organizationIdentifier) {

  /**
   * Compact constructor enforcing model invariants and providing defaults.
   */
  public CertificateConfig {
    if (id == null || id.isBlank()) {
      throw new IllegalArgumentException("Certificate 'id' is required and cannot be blank");
    }
    if (ca == null || ca.isBlank()) {
      throw new IllegalArgumentException(
          "Certificate 'ca' is required for certificate: %s".formatted(id));
    }
    if (keystore == null || keystore.isBlank()) {
      throw new IllegalArgumentException(
          "Certificate 'keystore' path is required for certificate: %s".formatted(id));
    }
    boolean hasEnv = passwordEnv != null && !passwordEnv.isBlank();
    boolean hasFile = passwordFile != null && !passwordFile.isBlank();
    if (!hasEnv && !hasFile) {
      throw new IllegalArgumentException(
          "Certificate '%s' must specify passwordEnv or passwordFile".formatted(id));
    }

    sans = sans != null ? List.copyOf(sans) : List.of();
    if (country == null || country.isBlank()) {
      country = "SE";
    }
  }
}
