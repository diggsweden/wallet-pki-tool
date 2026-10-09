// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.generator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.config.AuthorityConfig;
import se.digg.wallet.pki.config.CertificateConfig;
import se.digg.wallet.pki.config.CertificateConfigTestBuilder;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.PkiConfigurationException;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.config.TrustListConfig;
import se.digg.wallet.pki.crypto.KeystoreManager;

class PkiEngineTest {

  private PkiEngine pkiEngine;
  private KeystoreManager keystoreManager;
  private Map<String, String> mockSecrets;

  @BeforeEach
  void setUp() {
    mockSecrets =
        Map.of(
            "TEST_VERIFIER_KEYSTORE_PASSWORD", "verifier-secret-123",
            "TEST_PID_ISSUER_KEYSTORE_PASSWORD", "pid-issuer-secret-123",
            "TEST_PROVIDER_KEYSTORE_PASSWORD", "provider-secret-123");

    SecretResolver secretResolver = new SecretResolver(mockSecrets::get);
    pkiEngine =
        new PkiEngine(
            new se.digg.wallet.pki.crypto.EcKeyGenerator(),
            new se.digg.wallet.pki.crypto.CertificateAuthorityManager(),
            new se.digg.wallet.pki.crypto.CertificateProfileIssuer(),
            new KeystoreManager(),
            secretResolver);
    keystoreManager = new KeystoreManager();
  }

  @Test
  void shouldGenerateFullEcosystemArtifacts(@TempDir Path tempDir) throws Exception {
    // 1. Build test configuration
    PkiConfiguration config = createTestConfiguration(tempDir);

    // 2. Execute full generation
    pkiEngine.generate(config, null, null);

    // 3. Verify CA directories and files exist
    Path caDir = tempDir.resolve("ca");
    assertThat(Files.exists(caDir.resolve("verifier-access-ca/ca.pem"))).isTrue();
    assertThat(Files.exists(caDir.resolve("pid-issuer-ca/ca.pem"))).isTrue();
    assertThat(Files.exists(caDir.resolve("wallet-provider-ca/ca.pem"))).isTrue();
    assertThat(Files.exists(caDir.resolve("trust-source-ca/ca.pem"))).isTrue();

    // 4. Verify Verifier Access keystore
    Path verifierP12 =
        tempDir.resolve("verifier-access-certificate/verifier-access-certificate.p12");
    assertThat(Files.exists(verifierP12)).isTrue();
    KeyStore verifierStore =
        keystoreManager.loadKeyStore(verifierP12, "verifier-secret-123".toCharArray());
    assertThat(verifierStore.containsAlias("verifier_access_certificate")).isTrue();

    // 5. Verify PID Issuer multi-key keystore (3 aliases)
    Path pidP12 = tempDir.resolve("issuer/pid_issuer.p12");
    assertThat(Files.exists(pidP12)).isTrue();
    KeyStore pidStore =
        keystoreManager.loadKeyStore(pidP12, "pid-issuer-secret-123".toCharArray());
    assertThat(pidStore.size()).isEqualTo(3);
    assertThat(pidStore.containsAlias("pid_issuer")).isTrue();
    assertThat(pidStore.containsAlias("nonce-encryption")).isTrue();
    assertThat(pidStore.containsAlias("request-encryption")).isTrue();

    // 6. Verify Wallet Provider keystore
    Path providerP12 = tempDir.resolve("wallet-provider/wallet_provider.p12");
    assertThat(Files.exists(providerP12)).isTrue();
    KeyStore providerStore =
        keystoreManager.loadKeyStore(providerP12, "provider-secret-123".toCharArray());
    assertThat(providerStore.containsAlias("wallet_provider")).isTrue();

    // 7. Verify Truststore
    Path trustStorePath = tempDir.resolve("trusted_issuers.p12");
    assertThat(Files.exists(trustStorePath)).isTrue();
    KeyStore trustStore =
        keystoreManager.loadKeyStore(trustStorePath, "verifier-secret-123".toCharArray());
    assertThat(trustStore.size()).isEqualTo(2);
    assertThat(trustStore.isCertificateEntry("pid_issuer")).isTrue();
    assertThat(trustStore.isCertificateEntry("pid_issuer_ca")).isTrue();
  }

  @Test
  void shouldGenerateSelectiveTarget(@TempDir Path tempDir) throws Exception {
    // 1. Build test configuration
    PkiConfiguration config = createTestConfiguration(tempDir);

    // 2. Execute selective generation for verifier-access-certificate only
    pkiEngine.generate(config, List.of("verifier-access-certificate"), null);

    // 3. Verify selected target is created
    Path verifierP12 =
        tempDir.resolve("verifier-access-certificate/verifier-access-certificate.p12");
    assertThat(Files.exists(verifierP12)).isTrue();

    // 4. Verify unselected targets were not created
    Path pidP12 = tempDir.resolve("issuer/pid_issuer.p12");
    Path providerP12 = tempDir.resolve("wallet-provider/wallet_provider.p12");
    assertThat(Files.exists(pidP12)).isFalse();
    assertThat(Files.exists(providerP12)).isFalse();
  }

  @Test
  void shouldThrowWhenCertificateReferencesUnknownAuthority(@TempDir Path tempDir) {
    CertificateConfig invalidCert =
        CertificateConfigTestBuilder.builder()
            .id("bad-cert")
            .type("relying-party-access")
            .ca("non-existent-ca")
            .keystore("bad.p12")
            .passwordEnv("TEST_VERIFIER_KEYSTORE_PASSWORD")
            .build();

    PkiConfiguration config =
        new PkiConfiguration(
            "test",
            tempDir.toString(),
            List.of(new AuthorityConfig("valid-ca", "Valid CA")),
            List.of(invalidCert),
            List.of());

    assertThatThrownBy(() -> pkiEngine.generate(config, null, null))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining(
            "Certificate 'bad-cert' references unknown authority 'non-existent-ca'");
  }

  @Test
  void shouldSkipTruststoreDuringSelectivePidRotationWhenVerifierSecretMissing(
      @TempDir Path tempDir) throws Exception {
    // 1. Setup engine where ONLY pid-issuer secret is provided (verifier secret missing)
    Map<String, String> selectiveSecrets =
        Map.of("TEST_PID_ISSUER_KEYSTORE_PASSWORD", "pid-issuer-secret-123");

    PkiEngine selectiveEngine =
        new PkiEngine(
            new se.digg.wallet.pki.crypto.EcKeyGenerator(),
            new se.digg.wallet.pki.crypto.CertificateAuthorityManager(),
            new se.digg.wallet.pki.crypto.CertificateProfileIssuer(),
            new KeystoreManager(),
            new SecretResolver(selectiveSecrets::get));

    PkiConfiguration config = createTestConfiguration(tempDir);

    // 2. Generate selectively for pid-issuer
    selectiveEngine.generate(config, List.of("pid-issuer"), null);

    // 3. Verify PID keystore is generated, and truststore was skipped without failure
    Path pidP12 = tempDir.resolve("issuer/pid_issuer.p12");
    assertThat(Files.exists(pidP12)).isTrue();
    Path trustStorePath = tempDir.resolve("trusted_issuers.p12");
    assertThat(Files.exists(trustStorePath)).isFalse();
  }

  private PkiConfiguration createTestConfiguration(Path outputDir) {
    List<AuthorityConfig> authorities =
        List.of(
            new AuthorityConfig("verifier-access-ca", "DIGG Wallet Verifier Access CA"),
            new AuthorityConfig("pid-issuer-ca", "DIGG Wallet PID Issuer CA"),
            new AuthorityConfig("wallet-provider-ca", "DIGG Wallet Provider CA"),
            new AuthorityConfig("trust-source-ca", "DIGG Wallet Trust Source CA"));

    List<CertificateConfig> certificates =
        List.of(
            CertificateConfigTestBuilder.verifierAccessCertificate().build(),
            CertificateConfigTestBuilder.pidIssuer().build(),
            CertificateConfigTestBuilder.walletProvider().build());

    List<TrustListConfig> trustLists =
        List.of(
            new TrustListConfig(
                "lote",
                "etsi-119-602-lote",
                "trust-source-ca",
                "./trust-source/signed/trusted-entities.json"));

    return new PkiConfiguration("local", outputDir.toString(), authorities, certificates,
        trustLists);
  }
}
