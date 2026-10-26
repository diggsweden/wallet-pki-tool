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
  void passwords_are_resolved_from_the_named_environment_variable() {
    assertThat(new SecretResolver(name -> name.equals("PASSWORD") ? "test-value" : null)
        .resolve(new PasswordSource("PASSWORD", null))).containsExactly("test-value".toCharArray());
  }

  @Test
  void password_files_allow_trailing_newlines_and_preserve_leading_spaces(@TempDir Path directory)
      throws Exception {
    Path file = directory.resolve("password");
    Files.writeString(file, "  test-value\n");
    assertThat(new SecretResolver(name -> null).resolve(new PasswordSource(null, file.toString())))
        .containsExactly("  test-value".toCharArray());
  }

  @Test
  void missing_environment_passwords_are_rejected() {
    assertThatThrownBy(
        () -> new SecretResolver(name -> null).resolve(new PasswordSource("PASSWORD", null)))
        .hasMessageContaining("not set or empty");
  }

  @Test
  void empty_password_files_are_rejected(@TempDir Path directory) throws Exception {
    Path file = directory.resolve("password");
    Files.writeString(file, "\n");
    assertThatThrownBy(
        () -> new SecretResolver().resolve(new PasswordSource(null, file.toString())))
        .hasMessageContaining("not set or empty");
  }

  @Test
  void unreadable_password_files_are_rejected() {
    assertThatThrownBy(
        () -> new SecretResolver().resolve(new PasswordSource(null, "missing-password.txt")))
        .hasMessageContaining("Cannot read password file");
  }
}
