// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.domain;

/** Fixed ecosystem CA subjects and their state/publication directory names. */
public enum AuthorityRole {
  PID_ISSUER("pid-issuer", "DIGG Wallet PID Issuer CA"),
  WALLET_PROVIDER("wallet-provider", "DIGG Wallet Provider CA"),
  VERIFIER_ACCESS("verifier-access-certificate", "DIGG Wallet Verifier Access Certificate CA"),
  VERIFIER_REGISTRATION("verifier-registration-certificate",
      "DIGG Wallet Verifier Registration Certificate CA"),
  TRUST_SOURCE("trust-source", "DIGG Wallet Trust Source CA");

  private final String directory;
  private final String commonName;

  AuthorityRole(String directory, String commonName) {
    this.directory = directory;
    this.commonName = commonName;
  }

  public String directory() {
    return directory;
  }

  public String commonName() {
    return commonName;
  }
}
