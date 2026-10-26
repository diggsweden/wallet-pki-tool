// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import java.security.cert.X509Certificate;
import se.digg.wallet.pki.config.LoteConfig;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.domain.Checks;

/** A resolved public CA certificate and its explicitly configured LoTE role and metadata. */
public record LoteAuthority(AuthorityRole role, X509Certificate certificate,
    LoteConfig.Entity entity) {
  public LoteAuthority {
    Checks.required(role, "LoTE authority role");
    Checks.required(certificate, "LoTE authority certificate");
    Checks.required(entity, "LoTE authority metadata");
    if (certificate.getBasicConstraints() < 0) {
      throw new IllegalArgumentException("LoTE requires a CA certificate for " + role.directory());
    }
  }
}
