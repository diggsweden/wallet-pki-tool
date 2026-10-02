// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigurationLoaderTest {

  private ConfigurationLoader loader;

  @BeforeEach
  void setUp() {
    loader = new ConfigurationLoader();
  }

  @Test
  void shouldLoadValidConfiguration() {
    Path configPath = Path.of("src/test/resources/test-ecosystem.yaml");
    PkiConfiguration config = loader.load(configPath);

    assertThat(config).isNotNull();
    assertThat(config.getEnvironment()).isEqualTo("local");
    assertThat(config.getOutputDir()).isEqualTo("./target/test-certificates");
    assertThat(config.getAuthorities()).hasSize(4);
    assertThat(config.getCertificates()).hasSize(3);
    assertThat(config.getTrustLists()).hasSize(1);

    CertificateConfig verifierCert = config.getCertificates().get(0);
    assertThat(verifierCert.getId()).isEqualTo("verifier-access-certificate");
    assertThat(verifierCert.getType()).isEqualTo("relying-party-access");
    assertThat(verifierCert.getCa()).isEqualTo("verifier-access-ca");
    assertThat(verifierCert.getSans()).containsExactly("localhost", "verifier-backend");
  }

  @Test
  void shouldThrowWhenFileNotFound() {
    Path nonExistent = Path.of("non-existent-config.yaml");

    assertThatThrownBy(() -> loader.load(nonExistent))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("Configuration file not found");
  }

  @Test
  void shouldThrowWhenPathIsDirectory(@TempDir Path tempDir) {
    assertThatThrownBy(() -> loader.load(tempDir))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("is a directory, not a file");
  }

  @Test
  void shouldThrowWhenOutputDirIsMissing(@TempDir Path tempDir) throws IOException {
    Path invalidYaml = tempDir.resolve("no-output.yaml");
    Files.writeString(
        invalidYaml,
        """
            environment: local
            authorities:
              - id: ca-1
                commonName: "Test CA"
            """);

    assertThatThrownBy(() -> loader.load(invalidYaml))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("Field 'outputDir' is required");
  }

  @Test
  void shouldThrowWhenDuplicateAuthorityId(@TempDir Path tempDir) throws IOException {
    Path invalidYaml = tempDir.resolve("duplicate-ca.yaml");
    Files.writeString(
        invalidYaml,
        """
            outputDir: ./certs
            authorities:
              - id: ca-1
                commonName: "CA One"
              - id: ca-1
                commonName: "CA Two"
            """);

    assertThatThrownBy(() -> loader.load(invalidYaml))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("Duplicate authority ID found: ca-1");
  }

  @Test
  void shouldThrowWhenCertificateReferencesUnknownAuthority(@TempDir Path tempDir)
      throws IOException {
    Path invalidYaml = tempDir.resolve("unknown-ca.yaml");
    Files.writeString(
        invalidYaml,
        """
            outputDir: ./certs
            authorities:
              - id: ca-1
                commonName: "CA One"
            certificates:
              - id: cert-1
                ca: non-existent-ca
                keystore: ./cert1.p12
                passwordEnv: PASS_ENV
            """);

    assertThatThrownBy(() -> loader.load(invalidYaml))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("references unknown authority 'non-existent-ca'");
  }

  @Test
  void shouldThrowWhenCertificateHasNoPasswordConfig(@TempDir Path tempDir) throws IOException {
    Path invalidYaml = tempDir.resolve("no-password.yaml");
    Files.writeString(
        invalidYaml,
        """
            outputDir: ./certs
            authorities:
              - id: ca-1
                commonName: "CA One"
            certificates:
              - id: cert-1
                ca: ca-1
                keystore: ./cert1.p12
            """);

    assertThatThrownBy(() -> loader.load(invalidYaml))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("must specify passwordEnv or passwordFile");
  }
}
