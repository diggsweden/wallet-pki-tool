// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EcKeyGeneratorTest {

  private final EcKeyGenerator keyGenerator = new EcKeyGenerator();

  @Test
  void generated_keys_use_the_p256_curve() {
    KeyPair keyPair = keyGenerator.generateKeyPair();

    assertThat(keyPair.getPublic()).isInstanceOf(ECPublicKey.class);

    ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
    assertThat(ecPublicKey.getAlgorithm()).isEqualTo("EC");
    assertThat(ecPublicKey.getParams().getCurve().getField().getFieldSize()).isEqualTo(256);
  }

  @Test
  void successive_generations_produce_distinct_key_pairs() {
    KeyPair first = keyGenerator.generateKeyPair();

    KeyPair second = keyGenerator.generateKeyPair();

    assertThat(second.getPublic().getEncoded()).isNotEqualTo(first.getPublic().getEncoded());
    assertThat(second.getPrivate().getEncoded()).isNotEqualTo(first.getPrivate().getEncoded());
  }

  @Test
  void private_keys_survive_pem_file_round_trips(@TempDir Path tempDir) throws IOException {
    KeyPair keyPair = keyGenerator.generateKeyPair();
    Path keyFile = tempDir.resolve("private_key.pem");

    keyGenerator.writePrivateKeyPem(keyPair.getPrivate(), keyFile);

    assertThat(Files.exists(keyFile)).isTrue();
    String pemContent = Files.readString(keyFile);
    assertThat(pemContent).contains("-----BEGIN");

    PrivateKey restoredKey = keyGenerator.readPrivateKeyPem(keyFile);
    assertThat(restoredKey.getEncoded()).isEqualTo(keyPair.getPrivate().getEncoded());
  }

  @Test
  void missing_private_key_files_report_the_path(@TempDir Path tempDir) {
    Path nonExistent = tempDir.resolve("does-not-exist.pem");

    assertThatThrownBy(() -> keyGenerator.readPrivateKeyPem(nonExistent))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Private key file not found");
  }

  @Test
  void malformed_private_keys_are_rejected() {
    String invalidContent = "THIS IS NOT A PEM FILE";

    assertThatThrownBy(() -> keyGenerator.readPrivateKeyPem(invalidContent))
        .isInstanceOf(PkiCryptoException.class);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void private_key_files_are_readable_by_container_users(boolean replacing,
      @TempDir Path tempDir) throws IOException {
    assumeTrue(Files.getFileAttributeView(tempDir, PosixFileAttributeView.class) != null);
    KeyPair keyPair = keyGenerator.generateKeyPair();
    Path keyFile = tempDir.resolve("private_key.pem");
    if (replacing) {
      Files.writeString(keyFile, "old key");
      Files.setPosixFilePermissions(keyFile, PosixFilePermissions.fromString("rw-------"));
    }

    keyGenerator.writePrivateKeyPem(keyPair.getPrivate(), keyFile);

    assertThat(Files.getPosixFilePermissions(keyFile))
        .isEqualTo(PosixFilePermissions.fromString("rw-r--r--"));
    assertThat(keyGenerator.readPrivateKeyPem(keyFile).getEncoded())
        .isEqualTo(keyPair.getPrivate().getEncoded());
  }
}
