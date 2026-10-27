// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

/** Exception thrown when PKI configuration validation or loading fails. */
public class PkiConfigurationException extends RuntimeException {

  public PkiConfigurationException(String message) {
    super(message);
  }

  public PkiConfigurationException(String message, Throwable cause) {
    super(message, cause);
  }
}
