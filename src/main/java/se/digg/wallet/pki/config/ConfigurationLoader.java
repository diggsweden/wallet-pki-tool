// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

/** Loads and validates PKI YAML configuration files. */
public class ConfigurationLoader {

  private final ObjectMapper yamlMapper;

  /** Default constructor initializing the YAML mapper. */
  public ConfigurationLoader() {
    this.yamlMapper = new YAMLMapper();
    this.yamlMapper.registerModule(new JavaTimeModule());
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
      throw new PkiConfigurationException("Configuration file not found: " + configPath);
    }

    if (Files.isDirectory(configPath)) {
      throw new PkiConfigurationException(
          "Configuration path is a directory, not a file: " + configPath);
    }

    PkiConfiguration config;
    try {
      config = yamlMapper.readValue(configPath.toFile(), PkiConfiguration.class);
    } catch (IOException e) {
      throw new PkiConfigurationException(
          "Failed to parse YAML configuration file: " + configPath, e);
    }

    validate(config, configPath.toFile());
    return config;
  }

  /**
   * Validates the configuration model.
   *
   * @param config the configuration to validate
   * @param sourceFile the source file reference for error reporting
   */
  private void validate(PkiConfiguration config, File sourceFile) {
    if (config == null) {
      throw new PkiConfigurationException(
          "Configuration is empty in file: " + sourceFile.getPath());
    }

    if (config.getOutputDir() == null || config.getOutputDir().isBlank()) {
      throw new PkiConfigurationException(
          "Field 'outputDir' is required in configuration: " + sourceFile.getPath());
    }

    Set<String> authorityIds = new HashSet<>();
    for (AuthorityConfig authority : config.getAuthorities()) {
      if (authority.getId() == null || authority.getId().isBlank()) {
        throw new PkiConfigurationException("Authority ID is required in: " + sourceFile.getPath());
      }
      if (!authorityIds.add(authority.getId())) {
        throw new PkiConfigurationException("Duplicate authority ID found: " + authority.getId());
      }
      if (authority.getCommonName() == null || authority.getCommonName().isBlank()) {
        throw new PkiConfigurationException(
            "Authority 'commonName' is required for: " + authority.getId());
      }
    }

    Set<String> certificateIds = new HashSet<>();
    for (CertificateConfig certificate : config.getCertificates()) {
      if (certificate.getId() == null || certificate.getId().isBlank()) {
        throw new PkiConfigurationException(
            "Certificate ID is required in: " + sourceFile.getPath());
      }
      if (!certificateIds.add(certificate.getId())) {
        throw new PkiConfigurationException(
            "Duplicate certificate ID found: " + certificate.getId());
      }
      if (certificate.getCa() == null || certificate.getCa().isBlank()) {
        throw new PkiConfigurationException(
            "Certificate 'ca' is required for: " + certificate.getId());
      }
      if (!authorityIds.contains(certificate.getCa())) {
        throw new PkiConfigurationException(
            String.format(
                "Certificate '%s' references unknown authority '%s'",
                certificate.getId(), certificate.getCa()));
      }
      if (certificate.getKeystore() == null || certificate.getKeystore().isBlank()) {
        throw new PkiConfigurationException(
            "Certificate 'keystore' path is required for: " + certificate.getId());
      }
      boolean hasEnv =
          certificate.getPasswordEnv() != null && !certificate.getPasswordEnv().isBlank();
      boolean hasFile =
          certificate.getPasswordFile() != null && !certificate.getPasswordFile().isBlank();
      if (!hasEnv && !hasFile) {
        throw new PkiConfigurationException(
            "Certificate '" + certificate.getId() + "' must specify passwordEnv or passwordFile");
      }
    }

    Set<String> trustListIds = new HashSet<>();
    for (TrustListConfig trustList : config.getTrustLists()) {
      if (trustList.getId() == null || trustList.getId().isBlank()) {
        throw new PkiConfigurationException("TrustList ID is required in: " + sourceFile.getPath());
      }
      if (!trustListIds.add(trustList.getId())) {
        throw new PkiConfigurationException("Duplicate trustList ID found: " + trustList.getId());
      }
      if (trustList.getOutputFile() == null || trustList.getOutputFile().isBlank()) {
        throw new PkiConfigurationException(
            "TrustList 'outputFile' path is required for: " + trustList.getId());
      }
    }
  }
}
