// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

/** Exception thrown when PKI configuration validation or loading fails. */
public class PkiConfigurationException extends RuntimeException {

  /**
   * Constructs a new exception with specified message.
   *
   * @param message the detail message
   */
  public PkiConfigurationException(String message) {
    super(message);
  }

  /**
   * Constructs a new exception with specified message and cause.
   *
   * @param message the detail message
   * @param cause the root cause
   */
  public PkiConfigurationException(String message, Throwable cause) {
    super(message, cause);
  }
}
