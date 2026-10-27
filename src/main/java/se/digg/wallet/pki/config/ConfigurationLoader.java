// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.nio.file.Files;
import java.nio.file.Path;
import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.dataformat.yaml.YAMLFactory;
import tools.jackson.dataformat.yaml.YAMLMapper;

/**
 * Strict YAML boundary; records enforce the schema's invariants. Paths are relative to the working
 * directory.
 */
public class ConfigurationLoader {
  private final ObjectMapper yamlMapper = YAMLMapper
      .builder(YAMLFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build())
      .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
      .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();

  public PkiConfiguration load(Path configPath) {
    if (configPath == null || !Files.isRegularFile(configPath)) {
      throw new PkiConfigurationException("Configuration file not found: " + configPath);
    }
    try {
      PkiConfiguration config = yamlMapper.readValue(configPath.toFile(), PkiConfiguration.class);
      if (config == null) {
        throw new PkiConfigurationException("Configuration is empty: " + configPath);
      }
      return config;
    } catch (JacksonException e) {
      throw new PkiConfigurationException(
          "Invalid configuration in " + configPath + ": " + e.getMessage(), e);
    }
  }
}
