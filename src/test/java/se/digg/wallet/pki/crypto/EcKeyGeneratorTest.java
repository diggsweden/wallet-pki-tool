// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EcKeyGeneratorTest {

  private EcKeyGenerator keyGenerator;

  @BeforeEach
  void setUp() {
    keyGenerator = new EcKeyGenerator();
  }

  @Test
  void shouldGenerateValidEcP256KeyPair() {
    // 1. Generate EC key pair
    KeyPair keyPair = keyGenerator.generateKeyPair();

    // 2. Verify EC P-256 (secp256r1) key attributes
    assertThat(keyPair).isNotNull();
    assertThat(keyPair.getPrivate()).isNotNull();
    assertThat(keyPair.getPublic()).isNotNull();
    assertThat(keyPair.getPublic()).isInstanceOf(ECPublicKey.class);

    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
    assertThat(ecPublicKey.getAlgorithm()).isEqualTo("EC");
    assertThat(ecPublicKey.getParams().getCurve().getField().getFieldSize()).isEqualTo(256);
  }

  @Test
  void shouldConvertKeyToPemAndParseBack(@TempDir Path tempDir) throws IOException {
    // 1. Generate key pair and save private key as PEM file
    KeyPair keyPair = keyGenerator.generateKeyPair();
    Path keyFile = tempDir.resolve("private_key.pem");

    keyGenerator.writePrivateKeyPem(keyPair.getPrivate(), keyFile);

    assertThat(Files.exists(keyFile)).isTrue();
    String pemContent = Files.readString(keyFile);
    assertThat(pemContent).contains("-----BEGIN");

    // 2. Read back private key from PEM file and verify equality
    PrivateKey restoredKey = keyGenerator.readPrivateKeyPem(keyFile);
    assertThat(restoredKey).isNotNull();
    assertThat(restoredKey.getEncoded()).isEqualTo(keyPair.getPrivate().getEncoded());
  }

  @Test
  void shouldThrowWhenReadingNonExistentFile(@TempDir Path tempDir) {
    // Verify exception when private key file is missing
    Path nonExistent = tempDir.resolve("does-not-exist.pem");

    assertThatThrownBy(() -> keyGenerator.readPrivateKeyPem(nonExistent))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Private key file not found");
  }

  @Test
  void shouldThrowWhenParsingInvalidPem() {
    // Verify exception when PEM format is corrupt or invalid
    String invalidContent = "THIS IS NOT A PEM FILE";

    assertThatThrownBy(() -> keyGenerator.readPrivateKeyPem(invalidContent))
        .isInstanceOf(PkiCryptoException.class);
  }

  @Test
  void shouldSetOwnerOnlyPermissionsOnPrivateKeyFile(@TempDir Path tempDir) throws IOException {
    KeyPair keyPair = keyGenerator.generateKeyPair();
    Path keyFile = tempDir.resolve("owner_only_key.pem");

    keyGenerator.writePrivateKeyPem(keyPair.getPrivate(), keyFile);

    if (java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
      java.nio.file.attribute.PosixFilePermissions.fromString("rw-------");
      java.util.Set<java.nio.file.attribute.PosixFilePermission> perms =
          Files.getPosixFilePermissions(keyFile);
      assertThat(java.nio.file.attribute.PosixFilePermissions.toString(perms))
          .isEqualTo("rw-------");
    }
  }
}
