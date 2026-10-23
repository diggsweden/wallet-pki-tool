// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecretResolverTest {
  @Test
  void selected_environment_passwords_are_resolved() {
    var secrets = new SecretResolver(name -> name.equals("PASSWORD") ? "value" : null);

    assertThat(secrets.resolve(new PasswordSource("PASSWORD", null)))
        .isEqualTo("value".toCharArray());
  }

  @Test
  void missing_password_values_never_appear_in_errors() {
    var secrets = new SecretResolver(name -> null);

    assertThatThrownBy(() -> secrets.resolve(new PasswordSource("PASSWORD", null)))
        .isInstanceOf(PkiConfigurationException.class).hasMessageContaining("not set or empty");
  }

  @Test
  void password_files_preserve_spaces_and_strip_line_endings(@TempDir Path directory)
      throws Exception {
    Path file = directory.resolve("password");
    Files.writeString(file, " value \r\n");

    assertThat(new SecretResolver().resolve(new PasswordSource(null, file.toString())))
        .isEqualTo(" value ".toCharArray());
  }
}
