// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

/** Runtime exception thrown when a cryptographic or PKI operation fails. */
public class PkiCryptoException extends RuntimeException {

  public PkiCryptoException(String message) {
    super(message);
  }

  public PkiCryptoException(String message, Throwable cause) {
    super(message, cause);
  }
}
