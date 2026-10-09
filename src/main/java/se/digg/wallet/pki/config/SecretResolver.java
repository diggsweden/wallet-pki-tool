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

    // 1. Resolve from environment variable if configured
    if (config.passwordEnv() != null && !config.passwordEnv().isBlank()) {
      String value = envProvider.apply(config.passwordEnv());
      if (value == null || value.isBlank()) {
        throw new PkiConfigurationException(
            "Environment variable '%s' for certificate '%s' is not set or empty"
                .formatted(config.passwordEnv(), config.id()));
      }
      return value;
    }

    // 2. Resolve from password file if configured (e.g. Kubernetes secret volume)
    if (config.passwordFile() != null && !config.passwordFile().isBlank()) {
      Path path = Path.of(config.passwordFile());
      if (!Files.exists(path)) {
        throw new PkiConfigurationException(
            "Password file '%s' for certificate '%s' does not exist"
                .formatted(config.passwordFile(), config.id()));
      }
      try {
        return Files.readString(path, StandardCharsets.UTF_8).trim();
      } catch (IOException e) {
        throw new PkiConfigurationException(
            "Failed to read password file '%s' for certificate '%s'"
                .formatted(config.passwordFile(), config.id()),
            e);
      }
    }

    throw new PkiConfigurationException(
        "No password configuration (passwordEnv or passwordFile) specified for certificate '%s'"
            .formatted(config.id()));
  }
}
