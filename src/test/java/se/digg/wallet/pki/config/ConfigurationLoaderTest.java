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
    // 1. Load test configuration file
    Path configPath = Path.of("src/test/resources/test-ecosystem.yaml");
    PkiConfiguration config = loader.load(configPath);

    // 2. Verify parsed metadata, authorities, certificates, and trust lists
    assertThat(config).isNotNull();
    assertThat(config.environment()).isEqualTo("local");
    assertThat(config.outputDir()).isEqualTo("./target/test-certificates");
    assertThat(config.authorities()).hasSize(4);
    assertThat(config.certificates()).hasSize(3);
    assertThat(config.trustLists()).hasSize(1);

    CertificateConfig verifierCert = config.certificates().get(0);
    assertThat(verifierCert.id()).isEqualTo("verifier-access-certificate");
    assertThat(verifierCert.type()).isEqualTo("relying-party-access");
    assertThat(verifierCert.ca()).isEqualTo("verifier-access-ca");
    assertThat(verifierCert.sans()).containsExactly("localhost", "verifier-backend");
  }

  @Test
  void shouldThrowWhenFileNotFound() {
    // Verify exception when configuration file does not exist
    Path nonExistent = Path.of("non-existent-config.yaml");

    assertThatThrownBy(() -> loader.load(nonExistent))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("Configuration file not found");
  }

  @Test
  void shouldThrowWhenPathIsDirectory(@TempDir Path tempDir) {
    // Verify exception when configuration path points to a directory
    assertThatThrownBy(() -> loader.load(tempDir))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("is a directory, not a file");
  }

  @Test
  void shouldThrowWhenOutputDirIsMissing(@TempDir Path tempDir) throws IOException {
    // Verify validation error when required outputDir field is omitted
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
    // Verify validation error on duplicate authority IDs
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
    // Verify validation error when certificate references an undefined CA
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
    // Verify validation error when certificate lacks password configuration
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

  @Test
  void shouldThrowWhenTrustListReferencesUnknownSignerAuthority(@TempDir Path tempDir)
      throws IOException {
    Path invalidYaml = tempDir.resolve("unknown-trust-signer.yaml");
    Files.writeString(
        invalidYaml,
        """
            outputDir: ./certs
            authorities:
              - id: ca-1
                commonName: "CA One"
            trustLists:
              - id: lote
                type: etsi-119-602-lote
                signerAuthority: non-existent-ca
                outputFile: ./lote.jwt
            """);

    assertThatThrownBy(() -> loader.load(invalidYaml))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining(
            "Trust list 'lote' references unknown signer authority 'non-existent-ca'");
  }

  @Test
  void shouldThrowWhenTrustListReferencesUnknownEntity(@TempDir Path tempDir) throws IOException {
    Path invalidYaml = tempDir.resolve("unknown-entity.yaml");
    Files.writeString(
        invalidYaml,
        """
            outputDir: ./certs
            authorities:
              - id: ca-1
                commonName: "CA One"
            trustLists:
              - id: lote
                type: etsi-119-602-lote
                signerAuthority: ca-1
                outputFile: ./lote.jwt
                entities:
                  - unknown-entity-id
            """);

    assertThatThrownBy(() -> loader.load(invalidYaml))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("Trust list 'lote' references unknown entity 'unknown-entity-id'");
  }

  @Test
  void shouldThrowWhenDuplicateTrustListId(@TempDir Path tempDir) throws IOException {
    Path invalidYaml = tempDir.resolve("dup-trust-id.yaml");
    Files.writeString(
        invalidYaml,
        """
            outputDir: ./certs
            authorities:
              - id: ca-1
                commonName: "CA One"
            trustLists:
              - id: lote
                type: etsi-119-602-lote
                signerAuthority: ca-1
                outputFile: ./lote1.jwt
              - id: lote
                type: etsi-119-602-lote
                signerAuthority: ca-1
                outputFile: ./lote2.jwt
            """);

    assertThatThrownBy(() -> loader.load(invalidYaml))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("Duplicate trust list ID found: lote");
  }
}
