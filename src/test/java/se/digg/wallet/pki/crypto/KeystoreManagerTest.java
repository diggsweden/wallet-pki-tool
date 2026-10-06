// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.config.CertificateConfig;
import se.digg.wallet.pki.config.CertificateConfigTestBuilder;

class KeystoreManagerTest {

  private KeystoreManager keystoreManager;
  private EcKeyGenerator keyGenerator;
  private CertificateAuthorityManager caManager;
  private CertificateProfileIssuer issuer;

  @BeforeEach
  void setUp(@TempDir Path tempDir) {
    keystoreManager = new KeystoreManager();
    keyGenerator = new EcKeyGenerator();
    caManager = new CertificateAuthorityManager();
    issuer = new CertificateProfileIssuer();
  }

  @Test
  void shouldCreateAndSaveSingleKeyStore(@TempDir Path tempDir) throws Exception {
    // 1. Setup CA, service key pair, and certificate
    CertificateAuthority ca =
        caManager.createAuthority("wallet-provider-ca", "DIGG Wallet Provider CA");
    KeyPair serviceKeyPair = keyGenerator.generateKeyPair();

    CertificateConfig config =
        CertificateConfigTestBuilder.builder()
            .id("wallet-provider")
            .type("wallet-provider-service")
            .tradeName("Wallet Provider")
            .sans(List.of("localhost"))
            .build();

    X509Certificate serviceCert =
        issuer.issueCertificate(config, serviceKeyPair.getPublic(), ca);

    char[] password = "provider-secret-pass".toCharArray();
    Path p12Path = tempDir.resolve("wallet-provider/wallet_provider.p12");

    // 2. Create and save PKCS#12 keystore
    KeyStore keyStore =
        keystoreManager.createSingleKeyStore(
            "wallet_provider",
            serviceKeyPair.getPrivate(),
            serviceCert,
            ca.certificate(),
            password);

    keystoreManager.saveKeyStore(keyStore, p12Path, password);

    // 3. Load keystore from disk and verify entries
    KeyStore loadedStore = keystoreManager.loadKeyStore(p12Path, password);
    assertThat(loadedStore).isNotNull();
    assertThat(loadedStore.containsAlias("wallet_provider")).isTrue();
    assertThat(loadedStore.isKeyEntry("wallet_provider")).isTrue();

    Key recoveredKey = loadedStore.getKey("wallet_provider", password);
    assertThat(recoveredKey.getEncoded()).isEqualTo(serviceKeyPair.getPrivate().getEncoded());

    Certificate[] chain = loadedStore.getCertificateChain("wallet_provider");
    assertThat(chain).hasSize(2);
    assertThat(chain[0].getEncoded()).isEqualTo(serviceCert.getEncoded());
    assertThat(chain[1].getEncoded()).isEqualTo(ca.certificate().getEncoded());
  }

  @Test
  void shouldCreateMultiKeyMergedKeyStore(@TempDir Path tempDir) throws Exception {
    // 1. Setup CA, service certificate, and two encryption certificates
    CertificateAuthority ca =
        caManager.createAuthority("pid-issuer-ca", "DIGG Wallet PID Issuer CA");

    KeyPair primaryKey = keyGenerator.generateKeyPair();
    CertificateConfig primaryConfig =
        CertificateConfigTestBuilder.builder()
            .id("pid-issuer")
            .type("pid-issuer-service")
            .tradeName("PID Issuer")
            .sans(List.of("localhost"))
            .build();
    X509Certificate primaryCert =
        issuer.issueCertificate(primaryConfig, primaryKey.getPublic(), ca);

    KeyPair nonceKey = keyGenerator.generateKeyPair();
    X509Certificate nonceCert =
        issuer.issueEncryptionCertificate(
            "nonce-encryption", List.of("localhost"), "SE", nonceKey.getPublic(), ca);

    KeyPair requestKey = keyGenerator.generateKeyPair();
    X509Certificate requestCert =
        issuer.issueEncryptionCertificate(
            "request-encryption", List.of("localhost"), "SE", requestKey.getPublic(), ca);

    char[] password = "pid-issuer-secret".toCharArray();
    Path p12Path = tempDir.resolve("issuer/pid_issuer.p12");

    // 2. Add all 3 key entries into a single PKCS#12 keystore
    KeyStore keyStore = keystoreManager.createPkcs12KeyStore();
    keystoreManager.addKeyEntry(
        keyStore,
        "pid_issuer",
        primaryKey.getPrivate(),
        password,
        new Certificate[] {primaryCert, ca.certificate()});
    keystoreManager.addKeyEntry(
        keyStore,
        "nonce-encryption",
        nonceKey.getPrivate(),
        password,
        new Certificate[] {nonceCert, ca.certificate()});
    keystoreManager.addKeyEntry(
        keyStore,
        "request-encryption",
        requestKey.getPrivate(),
        password,
        new Certificate[] {requestCert, ca.certificate()});

    keystoreManager.saveKeyStore(keyStore, p12Path, password);

    // 3. Load keystore from disk and verify all 3 aliases exist
    KeyStore loadedStore = keystoreManager.loadKeyStore(p12Path, password);
    assertThat(loadedStore.size()).isEqualTo(3);
    assertThat(loadedStore.containsAlias("pid_issuer")).isTrue();
    assertThat(loadedStore.containsAlias("nonce-encryption")).isTrue();
    assertThat(loadedStore.containsAlias("request-encryption")).isTrue();

    Key recoveredNonce = loadedStore.getKey("nonce-encryption", password);
    assertThat(recoveredNonce.getEncoded()).isEqualTo(nonceKey.getPrivate().getEncoded());
  }

  @Test
  void shouldCreateTrustStoreWithCertificates(@TempDir Path tempDir) throws Exception {
    // 1. Setup CA and service certificate
    CertificateAuthority ca =
        caManager.createAuthority("pid-issuer-ca", "DIGG Wallet PID Issuer CA");
    KeyPair serviceKeyPair = keyGenerator.generateKeyPair();

    CertificateConfig config =
        CertificateConfigTestBuilder.builder()
            .id("pid-issuer")
            .type("pid-issuer-service")
            .tradeName("PID Issuer")
            .sans(List.of("localhost"))
            .build();
    X509Certificate serviceCert =
        issuer.issueCertificate(config, serviceKeyPair.getPublic(), ca);

    char[] password = "trust-store-password".toCharArray();
    Path p12Path = tempDir.resolve("trusted_issuers.p12");

    // 2. Create truststore and add trusted certificates
    KeyStore trustStore = keystoreManager.createPkcs12KeyStore();
    keystoreManager.addCertificateEntry(trustStore, "pid_issuer", serviceCert);
    keystoreManager.addCertificateEntry(trustStore, "pid_issuer_ca", ca.certificate());

    keystoreManager.saveKeyStore(trustStore, p12Path, password);

    // 3. Load truststore and verify certificate entries
    KeyStore loadedStore = keystoreManager.loadKeyStore(p12Path, password);
    assertThat(loadedStore.size()).isEqualTo(2);
    assertThat(loadedStore.isCertificateEntry("pid_issuer")).isTrue();
    assertThat(loadedStore.isCertificateEntry("pid_issuer_ca")).isTrue();
  }

  @Test
  void shouldThrowWhenLoadingWithWrongPassword(@TempDir Path tempDir) throws Exception {
    // 1. Save keystore with known password
    CertificateAuthority ca =
        caManager.createAuthority("test-ca", "DIGG Test CA");
    KeyPair serviceKeyPair = keyGenerator.generateKeyPair();
    CertificateConfig config =
        CertificateConfigTestBuilder.builder()
            .id("test-cert")
            .type("relying-party-access")
            .tradeName("Test")
            .organizationIdentifier("VATSE-12345678")
            .sans(List.of("localhost"))
            .build();
    X509Certificate serviceCert =
        issuer.issueCertificate(config, serviceKeyPair.getPublic(), ca);

    char[] correctPassword = "correct-password".toCharArray();
    Path p12Path = tempDir.resolve("test.p12");

    KeyStore keyStore =
        keystoreManager.createSingleKeyStore(
            "test_cert",
            serviceKeyPair.getPrivate(),
            serviceCert,
            ca.certificate(),
            correctPassword);
    keystoreManager.saveKeyStore(keyStore, p12Path, correctPassword);

    // 2. Verify exception when attempting to load with wrong password
    char[] wrongPassword = "wrong-password".toCharArray();
    assertThatThrownBy(() -> keystoreManager.loadKeyStore(p12Path, wrongPassword))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Failed to load PKCS#12 KeyStore");
  }

  @Test
  void shouldThrowWhenLoadingNonExistentFile() {
    // Verify exception when keystore file is missing on disk
    Path missingPath = Path.of("non-existent-keystore.p12");
    char[] password = "any-password".toCharArray();

    assertThatThrownBy(() -> keystoreManager.loadKeyStore(missingPath, password))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("KeyStore file not found");
  }
}
