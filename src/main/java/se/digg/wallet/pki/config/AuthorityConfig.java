// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import se.digg.wallet.pki.domain.Checks;

/** A managed authority or an explicitly supplied certificate/private-key pair. */
public record AuthorityConfig(Source source, String commonName, String certificateFile,
    String privateKeyFile, String crlFile) {
  public enum Source {
    @JsonProperty("managed")
    MANAGED,
    @JsonProperty("existing")
    EXISTING
  }

  public AuthorityConfig {
    Checks.required(source, "authority.source");
    if (source == Source.MANAGED) {
      Checks.text(commonName, "authority.commonName");
      if (certificateFile != null || privateKeyFile != null || crlFile != null) {
        throw new IllegalArgumentException(
            "Managed authorities cannot specify certificateFile or privateKeyFile");
      }
    } else {
      Checks.text(certificateFile, "authority.certificateFile");
      Checks.text(privateKeyFile, "authority.privateKeyFile");
      Checks.text(crlFile, "authority.crlFile");
      if (commonName != null)
        throw new IllegalArgumentException("Existing authority names come from their certificates");
    }
  }
}
