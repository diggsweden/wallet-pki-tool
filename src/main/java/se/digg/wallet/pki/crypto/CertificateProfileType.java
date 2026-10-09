// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import java.util.Arrays;

/** Supported certificate profile types for the EUDI wallet ecosystem. */
public enum CertificateProfileType {
  RELYING_PARTY_ACCESS("relying-party-access"),
  PID_ISSUER_SERVICE("pid-issuer-service"),
  WALLET_PROVIDER_SERVICE("wallet-provider-service"),
  TRUST_SOURCE_SIGNER("trust-source-signer"),
  ENCRYPTION("encryption"),
  GENERIC_SERVICE("service");

  private final String value;

  CertificateProfileType(String value) {
    this.value = value;
  }

  public String value() {
    return value;
  }

  /**
   * Checks if this profile type matches the given string value.
   *
   * @param stringValue string value to match
   * @return true if matches, false otherwise
   */
  public boolean matches(String stringValue) {
    return this.value.equalsIgnoreCase(stringValue != null ? stringValue.trim() : "");
  }

  /**
   * Resolves a CertificateProfileType from a string value.
   *
   * @param value the profile type string (case-insensitive)
   * @return the matching CertificateProfileType, or GENERIC_SERVICE if null/blank
   * @throws IllegalArgumentException if an unknown profile type is specified
   */
  public static CertificateProfileType fromString(String value) {
    if (value == null || value.isBlank()) {
      return GENERIC_SERVICE;
    }
    String trimmed = value.trim();
    return Arrays.stream(values())
        .filter(t -> t.value.equalsIgnoreCase(trimmed))
        .findFirst()
        .orElseThrow(
            () -> new IllegalArgumentException("Unknown certificate profile type: " + value));
  }
}
