// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import se.digg.wallet.pki.crypto.KeystoreManager;
import se.digg.wallet.pki.crypto.PkiCryptoException;

class ArtifactPermissionsIntegrationTest {
  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void public_artifacts_are_readable_by_container_users(boolean replacing,
      @TempDir Path directory) throws Exception {
    assumeTrue(Files.getFileAttributeView(directory, PosixFileAttributeView.class) != null);
    Path file = directory.resolve("issuer_wrprc.jwt");
    if (replacing) {
      Files.writeString(file, "old document");
      Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    }

    new ArtifactWriter().text(file, "public registration document");

    assertThat(Files.getPosixFilePermissions(file))
        .isEqualTo(PosixFilePermissions.fromString("rw-r--r--"));
    assertThat(Files.readString(file)).isEqualTo("public registration document");
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void keystores_are_readable_by_container_users(boolean replacing,
      @TempDir Path directory) throws Exception {
    assumeTrue(Files.getFileAttributeView(directory, PosixFileAttributeView.class) != null);
    var manager = new KeystoreManager();
    var store = manager.createPkcs12KeyStore();
    char[] password = "test-password".toCharArray();
    Path file = directory.resolve("issuer.p12");
    if (replacing) {
      Files.writeString(file, "old keystore");
      Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    }

    manager.saveKeyStore(store, file, password);

    assertThat(Files.getPosixFilePermissions(file))
        .isEqualTo(PosixFilePermissions.fromString("rw-r--r--"));
    assertThat(manager.loadKeyStore(file, password).size()).isZero();
    try (var files = Files.list(directory)) {
      assertThat(files.toList()).containsExactly(file);
    }
  }

  @Test
  void failed_keystore_writes_preserve_the_previous_file(@TempDir Path directory) throws Exception {
    var manager = new KeystoreManager();
    var uninitialized = KeyStore.getInstance("PKCS12");
    Path file = directory.resolve("issuer.p12");
    Files.writeString(file, "previous keystore");

    assertThatThrownBy(() -> manager.saveKeyStore(uninitialized, file, "password".toCharArray()))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Failed to save PKCS#12 KeyStore");

    assertThat(Files.readString(file)).isEqualTo("previous keystore");
    try (var files = Files.list(directory)) {
      assertThat(files.toList()).containsExactly(file);
    }
  }
}
