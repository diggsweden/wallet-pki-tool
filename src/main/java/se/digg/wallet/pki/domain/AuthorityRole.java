// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.domain;

/** Fixed authority identities and their publication directory names. */
public enum AuthorityRole {
  PID_ISSUER("pid-issuer"), WALLET_PROVIDER("wallet-provider"),
  VERIFIER_ACCESS("verifier-access-certificate"),
  VERIFIER_REGISTRATION("verifier-registration-certificate"), TRUST_SOURCE("trust-source");

  private final String directory;

  AuthorityRole(String directory) {
    this.directory = directory;
  }

  public String directory() {
    return directory;
  }
}
