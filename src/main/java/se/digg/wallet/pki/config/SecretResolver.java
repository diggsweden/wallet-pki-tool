// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Function;

/** Securely resolves secrets (passwords and private keys) from environment variables or files. */
public class SecretResolver {

  private final Function<String, String> envProvider;

  /** Default constructor using System::getenv. */
  public SecretResolver() {
    this(System::getenv);
  }

  /**
   * Constructor with explicit environment provider (useful for unit testing).
   *
   * @param envProvider function to resolve environment variables
   */
  public SecretResolver(Function<String, String> envProvider) {
    this.envProvider = Objects.requireNonNull(envProvider, "envProvider must not be null");
  }

  /**
   * Resolves the keystore password for a certificate configuration.
   *
   * @param config the certificate configuration
   * @return the resolved password as a string
   * @throws PkiConfigurationException if the secret cannot be resolved
   */
  public String resolveKeystorePassword(CertificateConfig config) {
    if (config == null) {
      throw new PkiConfigurationException("Certificate configuration cannot be null");
    }

    if (config.getPasswordEnv() != null && !config.getPasswordEnv().isBlank()) {
      String value = envProvider.apply(config.getPasswordEnv());
      if (value == null || value.isBlank()) {
        throw new PkiConfigurationException(
            String.format(
                "Environment variable '%s' for certificate '%s' is not set or empty",
                config.getPasswordEnv(), config.getId()));
      }
      return value;
    }

    if (config.getPasswordFile() != null && !config.getPasswordFile().isBlank()) {
      Path path = Path.of(config.getPasswordFile());
      if (!Files.exists(path)) {
        throw new PkiConfigurationException(
            String.format(
                "Password file '%s' for certificate '%s' does not exist",
                config.getPasswordFile(), config.getId()));
      }
      try {
        return Files.readString(path, StandardCharsets.UTF_8).trim();
      } catch (IOException e) {
        throw new PkiConfigurationException(
            String.format(
                "Failed to read password file '%s' for certificate '%s'",
                config.getPasswordFile(), config.getId()),
            e);
      }
    }

    throw new PkiConfigurationException(
        String.format(
            "No password configuration (passwordEnv or passwordFile) specified"
                + " for certificate '%s'",
            config.getId()));
  }
}
