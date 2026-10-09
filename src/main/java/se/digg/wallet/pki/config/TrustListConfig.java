// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/** Configuration model for a trust list (such as LoTE or OAuth Status List). */
@JsonIgnoreProperties(ignoreUnknown = true)
public record TrustListConfig(
    String id,
    String type,
    String signerAuthority,
    String outputFile,
    String url,
    List<String> entities) {

  public static final String TYPE_LOTE = "etsi-119-602-lote";
  public static final String TYPE_STATUS_LIST = "oauth-status-list";

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
      type = TYPE_LOTE;
    } else if (!TYPE_LOTE.equals(type) && !TYPE_STATUS_LIST.equals(type)) {
      throw new IllegalArgumentException(
          "Unsupported trust list type '%s' for: %s".formatted(type, id));
    }
    entities = entities != null ? List.copyOf(entities) : List.of();
  }

  /**
   * Convenience constructor for backward compatibility with 4 parameters.
   */
  public TrustListConfig(String id, String type, String signerAuthority, String outputFile) {
    this(id, type, signerAuthority, outputFile, null, List.of());
  }
}
