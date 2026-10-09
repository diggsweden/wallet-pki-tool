// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import se.digg.wallet.pki.config.CertificateConfig;
import se.digg.wallet.pki.config.CertificateConfigTestBuilder;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;

class LoteGeneratorTest {

  private LoteGenerator loteGenerator;
  private CertificateAuthorityManager caManager;
  private CertificateProfileIssuer issuer;
  private EcKeyGenerator keyGenerator;

  @BeforeEach
  void setUp() {
    loteGenerator = new LoteGenerator();
    caManager = new CertificateAuthorityManager();
    issuer = new CertificateProfileIssuer();
    keyGenerator = new EcKeyGenerator();
  }

  @Test
  void shouldBuildValidLoteDocument() {
    // 1. Setup sample CA certificates
    CertificateAuthority walletCa =
        caManager.createAuthority("wallet-provider-ca", "DIGG Wallet Provider CA");
    CertificateAuthority pidCa =
        caManager.createAuthority("pid-issuer-ca", "DIGG Wallet PID Issuer CA");

    X509Certificate walletCert = walletCa.certificate();
    X509Certificate pidCert = pidCa.certificate();

    // 2. Build LoTE document
    LoteDocument doc = loteGenerator.buildLoteDocument(walletCert, pidCert);

    // 3. Verify document structure according to ETSI TS 119 602
    assertThat(doc).isNotNull();
    assertThat(doc.lote()).isNotNull();

    LoteDocument.ListAndSchemeInformation schemeInfo = doc.lote().listAndSchemeInformation();
    assertThat(schemeInfo).isNotNull();
    assertThat(schemeInfo.loteVersionIdentifier()).isEqualTo(1);
    assertThat(schemeInfo.loteSequenceNumber()).isEqualTo(1);
    assertThat(schemeInfo.loteType())
        .isEqualTo("http://uri.etsi.org/19602/LoTEType/wallet-providers");
    assertThat(schemeInfo.schemeTerritory()).isEqualTo("SE");
    assertThat(schemeInfo.schemeOperatorName().get(0).value()).isEqualTo("DIGG");
    assertThat(schemeInfo.schemeName().get(0).value()).isEqualTo("Local LoTE");
    assertThat(schemeInfo.listIssueDateTime()).isNotNull();
    assertThat(schemeInfo.nextUpdate()).isNotNull();

    // Verify 2 Trusted Entities (Wallet Provider & PID Issuer)
    assertThat(doc.lote().trustedEntitiesList()).hasSize(2);

    LoteDocument.TrustedEntity entity1 = doc.lote().trustedEntitiesList().get(0);
    assertThat(entity1.trustedEntityInformation().teName().get(0).value())
        .isEqualTo("DIGG Wallet Provider CA");
    assertThat(entity1.trustedEntityServices()).hasSize(1);
    assertThat(
        entity1
            .trustedEntityServices()
            .get(0)
            .serviceInformation()
            .serviceTypeIdentifier())
        .isEqualTo("http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance");

    LoteDocument.TrustedEntity entity2 = doc.lote().trustedEntitiesList().get(1);
    assertThat(entity2.trustedEntityInformation().teName().get(0).value())
        .isEqualTo("DIGG Wallet PID Issuer CA");
    assertThat(entity2.trustedEntityServices()).hasSize(1);
    assertThat(
        entity2
            .trustedEntityServices()
            .get(0)
            .serviceInformation()
            .serviceTypeIdentifier())
        .isEqualTo("http://uri.etsi.org/19602/SvcType/PID/Issuance");
  }

  @Test
  void shouldBuildLoteWithDynamicServiceCertificatesAndSans() {
    CertificateAuthority signingCa =
        caManager.createAuthority("wallet-ca", "DIGG Wallet Root CA");
    KeyPair keyPair = keyGenerator.generateKeyPair();

    CertificateConfig walletCertConfig =
        CertificateConfigTestBuilder.walletProvider()
            .id("custom-wallet")
            .ca("wallet-ca")
            .tradeName("Custom Wallet Provider")
            .sans(List.of("URI:https://wallet.example.se", "wallet.example.se"))
            .country("SE")
            .build();

    X509Certificate walletCert =
        issuer.issueCertificate(walletCertConfig, keyPair.getPublic(), signingCa);

    LoteDocument doc = loteGenerator.buildLoteDocument(List.of(walletCert));

    assertThat(doc.lote().trustedEntitiesList()).hasSize(1);
    LoteDocument.TrustedEntity entity = doc.lote().trustedEntitiesList().get(0);
    assertThat(entity.trustedEntityInformation().teName().get(0).value())
        .isEqualTo("Custom Wallet Provider");
    assertThat(entity.trustedEntityInformation().teAddress().tePostalAddress().get(0).country())
        .isEqualTo("SE");
    assertThat(entity.trustedEntityInformation().teInformationUri())
        .extracting(LoteDocument.UriValue::uriValue)
        .containsExactly("https://wallet.example.se");
    assertThat(entity.trustedEntityInformation().teAddress().teElectronicAddress())
        .extracting(LoteDocument.UriValue::uriValue)
        .containsExactly("https://wallet.example.se");
  }

  @Test
  void shouldSerializeLoteToJson() {
    // 1. Build sample document
    CertificateAuthority walletCa =
        caManager.createAuthority("wallet-provider-ca", "DIGG Wallet Provider CA");
    CertificateAuthority pidCa =
        caManager.createAuthority("pid-issuer-ca", "DIGG Wallet PID Issuer CA");

    LoteDocument doc =
        loteGenerator.buildLoteDocument(walletCa.certificate(), pidCa.certificate());

    // 2. Serialize to JSON
    String json = loteGenerator.serializeLoteJson(doc);

    // 3. Verify JSON contents
    assertThat(json).isNotNull();
    assertThat(json)
        .contains("\"LoTE\"")
        .contains("\"ListAndSchemeInformation\"")
        .contains("\"TrustedEntitiesList\"")
        .contains("http://uri.etsi.org/19602/LoTEType/wallet-providers")
        .contains("DIGG Wallet Provider CA")
        .contains("DIGG Wallet PID Issuer CA")
        .contains("X509Certificates");
  }
}
