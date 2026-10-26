// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.domain;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/** An issued leaf certificate and its corresponding key pair. */
public record SigningIdentity(KeyPair keyPair, X509Certificate certificate) {
  public SigningIdentity {
    Checks.required(keyPair, "identity.keyPair");
    Checks.required(certificate, "identity.certificate");
    if (certificate.getBasicConstraints() >= 0
        || !Arrays.equals(keyPair.getPublic().getEncoded(),
            certificate.getPublicKey().getEncoded())) {
      throw new IllegalArgumentException("Identity requires a matching leaf certificate");
    }
  }
}
