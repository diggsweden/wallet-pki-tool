// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.domain.Checks;

/** Subject settings for the fixed local CA roles; only selected authorities are required. */
public record AuthoritiesConfig(Authority pidIssuer, Authority walletAttestationIssuer,
    Authority verifierAccess,
    Authority verifierRegistration, Authority trustSource) {
  public Authority require(AuthorityRole role) {
    return switch (role) {
      case PID_ISSUER -> Checks.required(pidIssuer, "authorities.pidIssuer");
      case WALLET_ATTESTATION_ISSUER ->
        Checks.required(walletAttestationIssuer, "authorities.walletAttestationIssuer");
      case VERIFIER_ACCESS -> Checks.required(verifierAccess, "authorities.verifierAccess");
      case VERIFIER_REGISTRATION ->
        Checks.required(verifierRegistration, "authorities.verifierRegistration");
      case TRUST_SOURCE -> Checks.required(trustSource, "authorities.trustSource");
    };
  }

  public record Authority(String commonName) {
    public Authority {
      Checks.text(commonName, "authority.commonName");
    }
  }
}
