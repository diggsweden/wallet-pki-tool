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
    Map<String, String> mockEnv = Map.of("MY_SECRET_PASS", "super-secret-123");
    SecretResolver resolver = new SecretResolver(mockEnv::get);

    CertificateConfig config = new CertificateConfig();
    config.setId("my-cert");
    config.setPasswordEnv("MY_SECRET_PASS");

    String resolved = resolver.resolveKeystorePassword(config);
    assertThat(resolved).isEqualTo("super-secret-123");
  }

  @Test
  void shouldThrowWhenEnvironmentVariableIsUnset() {
    SecretResolver resolver = new SecretResolver(key -> null);

    CertificateConfig config = new CertificateConfig();
    config.setId("my-cert");
    config.setPasswordEnv("UNSET_SECRET_PASS");

    assertThatThrownBy(() -> resolver.resolveKeystorePassword(config))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining(
            "Environment variable 'UNSET_SECRET_PASS' for certificate 'my-cert' is not set");
  }

  @Test
  void shouldResolvePasswordFromPasswordFile(@TempDir Path tempDir) throws IOException {
    Path secretFile = tempDir.resolve("secret.txt");
    Files.writeString(secretFile, "file-secret-password\n");

    SecretResolver resolver = new SecretResolver();

    CertificateConfig config = new CertificateConfig();
    config.setId("file-cert");
    config.setPasswordFile(secretFile.toString());

    String resolved = resolver.resolveKeystorePassword(config);
    assertThat(resolved).isEqualTo("file-secret-password");
  }

  @Test
  void shouldThrowWhenPasswordFileDoesNotExist() {
    SecretResolver resolver = new SecretResolver();

    CertificateConfig config = new CertificateConfig();
    config.setId("file-cert");
    config.setPasswordFile("non-existent-secret.txt");

    assertThatThrownBy(() -> resolver.resolveKeystorePassword(config))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining(
            "Password file 'non-existent-secret.txt' for certificate 'file-cert' does not exist");
  }

  @Test
  void shouldThrowWhenNoPasswordConfigSpecified() {
    SecretResolver resolver = new SecretResolver();

    CertificateConfig config = new CertificateConfig();
    config.setId("no-pass-cert");

    assertThatThrownBy(() -> resolver.resolveKeystorePassword(config))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("No password configuration (passwordEnv or passwordFile) specified");
  }
}
