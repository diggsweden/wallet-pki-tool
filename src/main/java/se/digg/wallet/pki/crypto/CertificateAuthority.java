// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Objects;

/** Represents a Certificate Authority (CA) with its key pair, certificate, and CRL. */
public record CertificateAuthority(
    String id, KeyPair keyPair, X509Certificate certificate, X509CRL crl) {

  /**
   * Compact constructor validating required fields.
   */
  public CertificateAuthority {
    Objects.requireNonNull(id, "id must not be null");
    Objects.requireNonNull(keyPair, "keyPair must not be null");
    Objects.requireNonNull(certificate, "certificate must not be null");
  }

  /**
   * Returns the private key of the CA key pair.
   *
   * @return the private key
   */
  public PrivateKey privateKey() {
    return keyPair.getPrivate();
  }

  /**
   * Returns the public key of the CA key pair.
   *
   * @return the public key
   */
  public PublicKey publicKey() {
    return keyPair.getPublic();
  }
}
