// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.Checks;

/** Four named trust anchors, without arbitrary references or inferred service types. */
public record LoteConfig(String name, int sequenceNumber, int validityDays,
    TrustedAuthorities trustedAuthorities) {
  public LoteConfig {
    Checks.text(name, "lote.name");
    Checks.positive(sequenceNumber, "lote.sequenceNumber");
    Checks.positive(validityDays, "lote.validityDays");
    Checks.required(trustedAuthorities, "lote.trustedAuthorities");
  }


  public record TrustedAuthorities(Entity pidIssuer, Entity walletProvider, Entity verifierAccess,
      Entity verifierRegistration) {
    public TrustedAuthorities {
      Checks.required(pidIssuer, "lote.trustedAuthorities.pidIssuer");
      Checks.required(walletProvider, "lote.trustedAuthorities.walletProvider");
      Checks.required(verifierAccess, "lote.trustedAuthorities.verifierAccess");
      Checks.required(verifierRegistration, "lote.trustedAuthorities.verifierRegistration");
    }
  }

  public record Entity(String entityName, String serviceName, String informationUrl,
      String streetAddress, String certificateFile) {
    public Entity {
      Checks.text(entityName, "lote entity.entityName");
      Checks.text(serviceName, "lote entity.serviceName");
      Checks.httpUrl(informationUrl, "lote entity.informationUrl");
      Checks.text(streetAddress, "lote entity.streetAddress");
    }
  }
}
