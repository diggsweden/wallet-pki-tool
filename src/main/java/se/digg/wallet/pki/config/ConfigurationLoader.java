// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.dataformat.yaml.YAMLMapper;

/** Loads and validates PKI YAML configuration files. */
public class ConfigurationLoader {

  private final ObjectMapper yamlMapper;

  /** Default constructor initializing the YAML mapper. */
  public ConfigurationLoader() {
    this.yamlMapper = YAMLMapper.builder().build();
  }

  /**
   * Loads and validates a PKI configuration from the given file path.
   *
   * @param configPath path to the YAML configuration file
   * @return the parsed and validated PkiConfiguration
   * @throws PkiConfigurationException if the file is missing, unreadable, or invalid
   */
  public PkiConfiguration load(Path configPath) {
    if (configPath == null) {
      throw new PkiConfigurationException("Configuration path cannot be null");
    }

    if (!Files.exists(configPath)) {
      throw new PkiConfigurationException("Configuration file not found: %s".formatted(configPath));
    }

    if (Files.isDirectory(configPath)) {
      throw new PkiConfigurationException(
          "Configuration path is a directory, not a file: %s".formatted(configPath));
    }

    PkiConfiguration config;
    try {
      config = yamlMapper.readValue(configPath.toFile(), PkiConfiguration.class);
    } catch (JacksonException e) {
      String message = e.getMessage();
      if (e.getCause() instanceof IllegalArgumentException iae) {
        message = iae.getMessage();
      }
      throw new PkiConfigurationException(
          "Failed to parse YAML configuration file: %s (%s)".formatted(configPath, message), e);
    }

    validateCrossModelRelations(config, configPath.toFile());
    return config;
  }

  /**
   * Validates relationships across different models in the configuration.
   *
   * @param config the configuration to validate
   * @param sourceFile the source file reference for error reporting
   */
  private void validateCrossModelRelations(PkiConfiguration config, File sourceFile) {
    if (config == null) {
      throw new PkiConfigurationException(
          "Configuration is empty in file: %s".formatted(sourceFile.getPath()));
    }

    // 1. Validate Certificate Authorities (unique IDs)
    Set<String> authorityIds = new HashSet<>();
    for (AuthorityConfig authority : config.authorities()) {
      if (!authorityIds.add(authority.id())) {
        throw new PkiConfigurationException(
            "Duplicate authority ID found: %s in %s".formatted(authority.id(),
                sourceFile.getPath()));
      }
    }

    // 2. Validate service certificates (unique IDs and existing CA references)
    Set<String> certificateIds = new HashSet<>();
    for (CertificateConfig certificate : config.certificates()) {
      if (!certificateIds.add(certificate.id())) {
        throw new PkiConfigurationException(
            "Duplicate certificate ID found: %s in %s"
                .formatted(certificate.id(), sourceFile.getPath()));
      }
      if (!authorityIds.contains(certificate.ca())) {
        throw new PkiConfigurationException(
            "Certificate '%s' references unknown authority '%s'"
                .formatted(certificate.id(), certificate.ca()));
      }
    }

    // 3. Validate trust lists (unique IDs and existing signer CA references)
    Set<String> trustListIds = new HashSet<>();
    for (TrustListConfig trustList : config.trustLists()) {
      if (!trustListIds.add(trustList.id())) {
        throw new PkiConfigurationException(
            "Duplicate trust list ID found: %s in %s"
                .formatted(trustList.id(), sourceFile.getPath()));
      }
      if (!authorityIds.contains(trustList.signerAuthority())) {
        throw new PkiConfigurationException(
            "Trust list '%s' references unknown signer authority '%s'"
                .formatted(trustList.id(), trustList.signerAuthority()));
      }
    }
  }
}
