// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.config.AuthorityConfig;

class CertificateAuthorityManagerTest {

  private static final int KEY_CERT_SIGN = 5;
  private static final int CRL_SIGN = 6;

  private CertificateAuthorityManager caManager;

  @BeforeEach
  void setUp() {
    caManager = new CertificateAuthorityManager();
  }

  @Test
  void shouldCreateValidRootCaAndCrl() throws Exception {
    // 1. Generate Root CA and empty CRL
    CertificateAuthority ca = caManager.createAuthority("test-ca", "DIGG Wallet Test CA");

    assertThat(ca).isNotNull();
    assertThat(ca.id()).isEqualTo("test-ca");
    assertThat(ca.privateKey()).isNotNull();
    assertThat(ca.publicKey()).isNotNull();

    // 2. Verify certificate subject and issuer DN
    X509Certificate cert = ca.certificate();
    assertThat(cert).isNotNull();
    assertThat(cert.getSubjectX500Principal().getName()).contains("CN=DIGG Wallet Test CA",
        "O=DIGG", "C=SE");
    assertThat(cert.getIssuerX500Principal()).isEqualTo(cert.getSubjectX500Principal());

    // Basic constraints (CA = true) and key usages (keyCertSign, cRLSign)
    assertThat(cert.getBasicConstraints()).isGreaterThanOrEqualTo(0);

    boolean[] keyUsage = cert.getKeyUsage();
    assertThat(keyUsage).isNotNull();
    assertThat(keyUsage[KEY_CERT_SIGN]).isTrue();
    assertThat(keyUsage[CRL_SIGN]).isTrue();

    // 3. Verify cryptographic self-signature on certificate and CRL
    cert.verify(ca.publicKey());

    X509CRL crl = ca.crl();
    assertThat(crl).isNotNull();
    assertThat(crl.getIssuerX500Principal()).isEqualTo(cert.getSubjectX500Principal());
    crl.verify(ca.publicKey());
  }

  @Test
  void shouldSaveAndReloadAuthorityFromDisk(@TempDir Path tempDir) throws Exception {
    // 1. Create and save CA files to destination directory
    CertificateAuthority ca =
        caManager.createAuthority("pid-issuer-ca", "DIGG Wallet PID Issuer CA");
    Path caDir = tempDir.resolve("ca").resolve("pid-issuer-ca");

    caManager.saveAuthority(ca, caDir);

    Path keyFile = caDir.resolve("ca_private_key.pem");
    Path certFile = caDir.resolve("ca.pem");
    Path crlFile = caDir.resolve("revocation-list.pem");

    assertThat(Files.exists(keyFile)).isTrue();
    assertThat(Files.exists(certFile)).isTrue();
    assertThat(Files.exists(crlFile)).isTrue();

    // 2. Reload CA from disk and verify key/certificate consistency
    AuthorityConfig config = new AuthorityConfig("pid-issuer-ca", "DIGG Wallet PID Issuer CA");

    CertificateAuthority reloaded = caManager.loadOrCreateAuthority(config, tempDir);
    assertThat(reloaded).isNotNull();
    assertThat(reloaded.id()).isEqualTo("pid-issuer-ca");
    assertThat(reloaded.privateKey().getEncoded()).isEqualTo(ca.privateKey().getEncoded());
    assertThat(reloaded.certificate().getEncoded()).isEqualTo(ca.certificate().getEncoded());
  }

  @Test
  void shouldLoadAuthorityFromConfigWithKeyAndCertFiles(@TempDir Path tempDir) throws Exception {
    // 1. Create CA files at explicit paths (Sealed Secrets workflow)
    CertificateAuthority original = caManager.createAuthority("custom-ca", "DIGG Custom CA");
    Path keyFile = tempDir.resolve("custom_key.pem");
    Path certFile = tempDir.resolve("custom_cert.pem");

    new EcKeyGenerator().writePrivateKeyPem(original.privateKey(), keyFile);
    new EcKeyGenerator().writePemFile(original.certificate(), certFile);

    AuthorityConfig config =
        new AuthorityConfig("custom-ca", "DIGG Custom CA", "EC_P256", keyFile.toString(),
            certFile.toString());

    // 2. Load CA via configuration and verify match
    CertificateAuthority loaded = caManager.loadOrCreateAuthority(config, tempDir);
    assertThat(loaded).isNotNull();
    assertThat(loaded.id()).isEqualTo("custom-ca");
    assertThat(loaded.certificate().getEncoded())
        .isEqualTo(original.certificate().getEncoded());
  }

  @Test
  void shouldThrowWhenCaDirectoryHasIncompleteFiles(@TempDir Path tempDir) throws Exception {
    CertificateAuthority original = caManager.createAuthority("broken-ca", "DIGG Broken CA");
    Path caDir = tempDir.resolve("ca").resolve("broken-ca");
    Files.createDirectories(caDir);

    // Only save private key, omitting ca.pem
    new EcKeyGenerator().writePrivateKeyPem(original.privateKey(),
        caDir.resolve("ca_private_key.pem"));

    AuthorityConfig config = new AuthorityConfig("broken-ca", "DIGG Broken CA");

    org.assertj.core.api.Assertions.assertThatThrownBy(
        () -> caManager.loadOrCreateAuthority(config, tempDir))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Incomplete CA files found");
  }

  @Test
  void shouldThrowWhenImportedPrivateKeyDoesNotMatchCertificate(@TempDir Path tempDir)
      throws Exception {
    CertificateAuthority ca1 = caManager.createAuthority("ca1", "DIGG CA 1");
    CertificateAuthority ca2 = caManager.createAuthority("ca2", "DIGG CA 2");

    Path keyFile = tempDir.resolve("ca1_key.pem");
    Path certFile = tempDir.resolve("ca2_cert.pem");

    new EcKeyGenerator().writePrivateKeyPem(ca1.privateKey(), keyFile);
    new EcKeyGenerator().writePemFile(ca2.certificate(), certFile);

    AuthorityConfig config =
        new AuthorityConfig("mismatched-ca", "DIGG Mismatched CA", "EC_P256", keyFile.toString(),
            certFile.toString());

    org.assertj.core.api.Assertions.assertThatThrownBy(
        () -> caManager.loadOrCreateAuthority(config, tempDir))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Private key does not match");
  }

  @Test
  void shouldThrowWhenAuthorityConfigHasOnlyKeyFile() {
    org.assertj.core.api.Assertions.assertThatThrownBy(
        () -> new AuthorityConfig("partial-ca", "Partial CA", "EC_P256", "/tmp/key.pem", null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Both 'keyFile' and 'certFile' must be provided");
  }

  @Test
  void shouldThrowWhenAuthorityConfigHasOnlyCertFile() {
    org.assertj.core.api.Assertions.assertThatThrownBy(
        () -> new AuthorityConfig("partial-ca", "Partial CA", "EC_P256", null, "/tmp/cert.pem"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Both 'keyFile' and 'certFile' must be provided");
  }

  @Test
  void shouldThrowWhenParsingInvalidCrl() {
    CertificateAuthority ca = caManager.createAuthority("temp-ca", "DIGG Temp CA");
    String certPem = new EcKeyGenerator().toPemString(ca.certificate());

    org.assertj.core.api.Assertions.assertThatThrownBy(
        () -> caManager.readCrlPem(certPem))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Unsupported CRL format");

    org.assertj.core.api.Assertions.assertThatThrownBy(
        () -> caManager.readCrlPem("not a pem content"))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("No PEM object found");
  }
}
