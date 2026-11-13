// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.nio.file.Path;
import java.util.List;
import se.digg.wallet.pki.domain.Checks;

/** Trust anchors grouped by explicit service type, with optional certificate file overrides. */
public record LoteConfig(String jwtFile, String name, Long sequenceNumber, int validityDays,
    TrustedAuthorities trustedAuthorities) {
  public LoteConfig(String jwtFile, String name, int validityDays,
      TrustedAuthorities trustedAuthorities) {
    this(jwtFile, name, null, validityDays, trustedAuthorities);
  }

  public LoteConfig {
    Checks.relativePath(jwtFile, "trustSource.lote.jwtFile");
    Checks.text(name, "lote.name");
    if (sequenceNumber != null) {
      Checks.positive(sequenceNumber, "lote.sequenceNumber");
    }
    Checks.positive(validityDays, "lote.validityDays");
    Checks.required(trustedAuthorities, "lote.trustedAuthorities");
  }

  public record TrustedAuthorities(List<Entity> pidIssuer, List<Entity> walletAttestationIssuer,
      List<Entity> verifierAccess, List<Entity> verifierRegistration) {
    public TrustedAuthorities {
      pidIssuer = pidIssuer == null ? List.of() : List.copyOf(pidIssuer);
      walletAttestationIssuer =
          walletAttestationIssuer == null ? List.of() : List.copyOf(walletAttestationIssuer);
      verifierAccess = verifierAccess == null ? List.of() : List.copyOf(verifierAccess);
      verifierRegistration =
          verifierRegistration == null ? List.of() : List.copyOf(verifierRegistration);
    }
  }

  public record Entity(String entityName, String serviceName, String informationUrl,
      String streetAddress, String caCertificateFile) {
    public Entity {
      Checks.text(entityName, "lote entity.entityName");
      Checks.text(serviceName, "lote entity.serviceName");
      Checks.httpUrl(informationUrl, "lote entity.informationUrl");
      Checks.text(streetAddress, "lote entity.streetAddress");
      if (caCertificateFile != null) {
        Path.of(Checks.text(caCertificateFile, "lote entity.caCertificateFile"));
      }
    }
  }
}
