// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.domain;

import java.security.cert.X509Certificate;

/** Four explicitly assigned CA certificates, independent of their subject names. */
public record WalletTrustAnchors(X509Certificate pidIssuer, X509Certificate walletProvider,
    X509Certificate verifierAccess, X509Certificate verifierRegistration) {
  public WalletTrustAnchors {
    requireAuthority(pidIssuer, "PID issuer");
    requireAuthority(walletProvider, "wallet provider");
    requireAuthority(verifierAccess, "verifier access");
    requireAuthority(verifierRegistration, "verifier registration");
  }

  private static void requireAuthority(X509Certificate certificate, String role) {
    Checks.required(certificate, role);
    if (certificate.getBasicConstraints() < 0) {
      throw new IllegalArgumentException("LoTE requires the " + role + " CA certificate");
    }
  }
}
