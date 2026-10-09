// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecretResolverTest {

  @Test
  void shouldResolvePasswordFromEnvironmentVariable() {
    // 1. Mock environment variable provider
    Map<String, String> mockEnv = Map.of("MY_SECRET_PASS", "super-secret-123");
    SecretResolver resolver = new SecretResolver(mockEnv::get);

    CertificateConfig config =
        CertificateConfigTestBuilder.builder().id("my-cert").passwordEnv("MY_SECRET_PASS")
            .build();

    // 2. Resolve password and verify match
    String resolved = resolver.resolveKeystorePassword(config);
    assertThat(resolved).isEqualTo("super-secret-123");
  }

  @Test
  void shouldThrowWhenEnvironmentVariableIsUnset() {
    // Verify exception when requested environment variable is unset
    SecretResolver resolver = new SecretResolver(key -> null);

    CertificateConfig config =
        CertificateConfigTestBuilder.builder().id("my-cert").passwordEnv("UNSET_SECRET_PASS")
            .build();

    assertThatThrownBy(() -> resolver.resolveKeystorePassword(config))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining(
            "Environment variable 'UNSET_SECRET_PASS' for certificate 'my-cert' is not set");
  }

  @Test
  void shouldResolvePasswordFromPasswordFile(@TempDir Path tempDir) throws IOException {
    // 1. Create temporary password file (Kubernetes secret mount scenario)
    Path secretFile = tempDir.resolve("secret.txt");
    Files.writeString(secretFile, "file-secret-password\n");

    SecretResolver resolver = new SecretResolver();

    CertificateConfig config =
        CertificateConfigTestBuilder.builder().id("file-cert")
            .passwordFile(secretFile.toString()).build();

    // 2. Resolve password from file and verify match
    String resolved = resolver.resolveKeystorePassword(config);
    assertThat(resolved).isEqualTo("file-secret-password");
  }

  @Test
  void shouldThrowWhenPasswordFileDoesNotExist() {
    // Verify exception when password file is missing on disk
    SecretResolver resolver = new SecretResolver();

    CertificateConfig config =
        CertificateConfigTestBuilder.builder()
            .id("file-cert")
            .passwordFile("non-existent-secret.txt")
            .build();

    assertThatThrownBy(() -> resolver.resolveKeystorePassword(config))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining(
            "Password file 'non-existent-secret.txt' for certificate 'file-cert' does not exist");
  }

  @Test
  void shouldThrowWhenNoPasswordConfigSpecified() {
    // Verify that creating a CertificateConfig without password configuration fails constructor
    // validation
    assertThatThrownBy(
        () -> CertificateConfigTestBuilder.builder()
            .id("no-pass-cert")
            .passwordEnv(null)
            .passwordFile(null)
            .build())
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("must specify passwordEnv or passwordFile");
  }
}
