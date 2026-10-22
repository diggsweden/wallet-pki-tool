// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.domain;

import se.digg.wallet.pki.crypto.CertificateAuthority;

/** A PID keystore cannot be assembled without all three identities. */
public record PidIssuerMaterial(CertificateAuthority authority, SigningIdentity signing,
    SigningIdentity nonceEncryption, SigningIdentity requestEncryption) {
  public PidIssuerMaterial {
    Checks.required(authority, "PID authority");
    Checks.required(signing, "PID signing identity");
    Checks.required(nonceEncryption, "PID nonce encryption identity");
    Checks.required(requestEncryption, "PID request encryption identity");
  }
}
