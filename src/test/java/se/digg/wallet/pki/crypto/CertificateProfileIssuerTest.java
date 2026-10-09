// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import se.digg.wallet.pki.config.CertificateConfig;
import se.digg.wallet.pki.config.CertificateConfigTestBuilder;

class CertificateProfileIssuerTest {

  private static final int DIGITAL_SIGNATURE = 0;
  private static final int NON_REPUDIATION = 1;
  private static final int KEY_ENCIPHERMENT = 2;
  private static final int DATA_ENCIPHERMENT = 3;
  private static final int KEY_AGREEMENT = 4;

  private CertificateProfileIssuer issuer;
  private CertificateAuthorityManager caManager;
  private EcKeyGenerator keyGenerator;

  @BeforeEach
  void setUp() {
    issuer = new CertificateProfileIssuer();
    caManager = new CertificateAuthorityManager();
    keyGenerator = new EcKeyGenerator();
  }

  @Test
  void shouldIssueRelyingPartyAccessCertificate() throws Exception {
    // 1. Setup CA, service key pair, and Relying Party Access configuration
    CertificateAuthority ca =
        caManager.createAuthority("verifier-access-ca", "DIGG Wallet Verifier Access CA");
    KeyPair serviceKeyPair = keyGenerator.generateKeyPair();

    CertificateConfig config =
        CertificateConfigTestBuilder.builder()
            .id("verifier-access-certificate")
            .type("relying-party-access")
            .tradeName("DIGG Verifier")
            .country("SE")
            .organizationIdentifier("VATSE-12345678")
            .sans(List.of("localhost", "verifier-backend", "https://localhost/demo-verifier"))
            .build();

    // 2. Issue the certificate
    X509Certificate cert = issuer.issueCertificate(config, serviceKeyPair.getPublic(), ca);

    // 3. Verify subject DN attributes (CN, O, C, organizationIdentifier)
    X500Name x500Subject = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
    assertThat(x500Subject.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString())
        .isEqualTo("DIGG Verifier");
    assertThat(x500Subject.getRDNs(BCStyle.O)[0].getFirst().getValue().toString())
        .isEqualTo("DIGG");
    assertThat(x500Subject.getRDNs(BCStyle.C)[0].getFirst().getValue().toString()).isEqualTo("SE");
    assertThat(
        x500Subject.getRDNs(BCStyle.ORGANIZATION_IDENTIFIER)[0].getFirst().getValue().toString())
        .isEqualTo("VATSE-12345678");

    // End-entity certificate (CA = false)
    assertThat(cert.getBasicConstraints()).isEqualTo(-1);

    // Key usage: digitalSignature and nonRepudiation
    boolean[] keyUsage = cert.getKeyUsage();
    assertThat(keyUsage[DIGITAL_SIGNATURE]).isTrue();
    assertThat(keyUsage[NON_REPUDIATION]).isTrue();

    // Extended key usage: clientAuth and serverAuth
    List<String> eku = cert.getExtendedKeyUsage();
    assertThat(eku).contains("1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1");

    // Subject alternative names
    Collection<List<?>> sans = cert.getSubjectAlternativeNames();
    assertThat(sans)
        .containsExactlyInAnyOrder(
            List.of(2, "localhost"),
            List.of(2, "verifier-backend"),
            List.of(6, "https://localhost/demo-verifier"));

    // 4. Verify signature validity against issuing CA
    cert.verify(ca.publicKey());
  }

  @Test
  void shouldIssueEudiServiceCertificateWithQcStatements() throws Exception {
    // 1. Setup CA, service key pair, and PID Issuer configuration
    CertificateAuthority ca =
        caManager.createAuthority("pid-issuer-ca", "DIGG Wallet PID Issuer CA");
    KeyPair serviceKeyPair = keyGenerator.generateKeyPair();

    CertificateConfig config =
        CertificateConfigTestBuilder.builder()
            .id("pid-issuer")
            .type("pid-issuer-service")
            .tradeName("PID Issuer (Ecosystem)")
            .sans(List.of("localhost", "pid-issuer"))
            .build();

    // 2. Issue the certificate
    X509Certificate cert = issuer.issueCertificate(config, serviceKeyPair.getPublic(), ca);

    // 3. Verify subject CN and qualified certificate statements (qcStatements)
    assertThat(cert.getSubjectX500Principal().getName()).contains("CN=PID Issuer (Ecosystem)");
    assertThat(cert.getBasicConstraints()).isEqualTo(-1);

    byte[] qcBytes = cert.getExtensionValue(Extension.qCStatements.getId());
    ASN1OctetString oct = ASN1OctetString.getInstance(qcBytes);
    ASN1Sequence qcSeq = ASN1Sequence.getInstance(oct.getOctets());

    assertThat(qcSeq.size()).isEqualTo(3);
    QCStatement statement0 = QCStatement.getInstance(qcSeq.getObjectAt(0));
    QCStatement statement1 = QCStatement.getInstance(qcSeq.getObjectAt(1));
    QCStatement statement2 = QCStatement.getInstance(qcSeq.getObjectAt(2));

    assertThat(statement0.getStatementId())
        .isEqualTo(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance);
    assertThat(statement1.getStatementId())
        .isEqualTo(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType);
    assertThat(statement1.getStatementInfo().toString()).contains("0.4.0.194126.1.1");
    assertThat(statement2.getStatementId())
        .isEqualTo(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType);
    assertThat(statement2.getStatementInfo().toString()).contains("0.4.0.194126.1.2");

    // 4. Verify signature validity against issuing CA
    cert.verify(ca.publicKey());
  }

  @Test
  void shouldIssueTrustSourceSignerCertificate() throws Exception {
    // 1. Setup CA, service key pair, and Trust Source signer configuration
    CertificateAuthority ca =
        caManager.createAuthority("trust-source-ca", "DIGG Wallet Trust Source CA");
    KeyPair serviceKeyPair = keyGenerator.generateKeyPair();

    CertificateConfig config =
        CertificateConfigTestBuilder.builder()
            .id("trust-source")
            .type("trust-source-signer")
            .tradeName("Trust Source (Ecosystem)")
            .sans(List.of("localhost", "trust-source"))
            .build();

    // 2. Issue the certificate
    X509Certificate cert = issuer.issueCertificate(config, serviceKeyPair.getPublic(), ca);

    // 3. Verify subject CN and electronic seal (eSeal) declaration
    assertThat(cert.getSubjectX500Principal().getName()).contains("CN=Trust Source (Ecosystem)");
    byte[] qcBytes = cert.getExtensionValue(Extension.qCStatements.getId());
    ASN1OctetString oct = ASN1OctetString.getInstance(qcBytes);
    ASN1Sequence qcSeq = ASN1Sequence.getInstance(oct.getOctets());

    assertThat(qcSeq.size()).isEqualTo(2);
    QCStatement statement0 = QCStatement.getInstance(qcSeq.getObjectAt(0));
    QCStatement statement1 = QCStatement.getInstance(qcSeq.getObjectAt(1));

    assertThat(statement0.getStatementId())
        .isEqualTo(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance);
    assertThat(statement1.getStatementId())
        .isEqualTo(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType);
    assertThat(statement1.getStatementInfo().toString()).contains("0.4.0.1862.1.6.2");

    // 4. Verify signature validity against issuing CA
    cert.verify(ca.publicKey());
  }

  @Test
  void shouldIssueEncryptionCertificate() throws Exception {
    // 1. Setup CA and service key pair for encryption
    CertificateAuthority ca =
        caManager.createAuthority("pid-issuer-ca", "DIGG Wallet PID Issuer CA");
    KeyPair serviceKeyPair = keyGenerator.generateKeyPair();

    // 2. Issue the encryption certificate
    X509Certificate cert =
        issuer.issueEncryptionCertificate(
            "nonce-encryption",
            List.of("localhost"),
            "SE",
            serviceKeyPair.getPublic(),
            ca);

    // 3. Verify subject CN and encryption key usages
    assertThat(cert.getSubjectX500Principal().getName()).contains("CN=nonce-encryption");

    boolean[] keyUsage = cert.getKeyUsage();
    assertThat(keyUsage[KEY_ENCIPHERMENT]).isTrue();
    assertThat(keyUsage[DATA_ENCIPHERMENT]).isTrue();
    assertThat(keyUsage[KEY_AGREEMENT]).isTrue();

    // 4. Verify signature validity against issuing CA
    cert.verify(ca.publicKey());
  }

  @Test
  @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
  void shouldIncludeSubjectAlternativeNamesWithDifferentTypes() throws Exception {
    // 1. Setup CA, service key pair, and SANs with DNS, IP, URI, and plain name
    CertificateAuthority ca =
        caManager.createAuthority("verifier-access-ca", "DIGG Wallet Verifier Access CA");
    KeyPair serviceKeyPair = keyGenerator.generateKeyPair();

    CertificateConfig config =
        CertificateConfigTestBuilder.builder()
            .id("verifier-access-certificate")
            .type("relying-party-access")
            .tradeName("DIGG Verifier")
            .organizationIdentifier("VATSE-12345678")
            .sans(
                List.of(
                    "localhost",
                    "DNS:api.example.com",
                    "IP:127.0.0.1",
                    "192.168.1.1",
                    "URI:https://example.com/api",
                    "https://verifier.digg.se"))
            .build();

    // 2. Issue the certificate
    X509Certificate cert = issuer.issueCertificate(config, serviceKeyPair.getPublic(), ca);

    // 3. Verify SAN entries with exact types and values
    Collection<List<?>> sans = cert.getSubjectAlternativeNames();
    assertThat(sans)
        .containsExactlyInAnyOrder(
            List.of(2, "localhost"),
            List.of(2, "api.example.com"),
            List.of(7, "127.0.0.1"),
            List.of(7, "192.168.1.1"),
            List.of(6, "https://example.com/api"),
            List.of(6, "https://verifier.digg.se"));
  }

  @Test
  void shouldThrowWhenRelyingPartyAccessMissingOrganizationIdentifier() {
    CertificateAuthority ca =
        caManager.createAuthority("verifier-access-ca", "DIGG Wallet Verifier Access CA");
    KeyPair serviceKeyPair = keyGenerator.generateKeyPair();

    CertificateConfig config =
        CertificateConfigTestBuilder.builder()
            .id("verifier-access-certificate")
            .type("relying-party-access")
            .tradeName("DIGG Verifier")
            .organizationIdentifier(null)
            .build();

    assertThatThrownBy(() -> issuer.issueCertificate(config, serviceKeyPair.getPublic(), ca))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("requires a non-blank 'organizationIdentifier'");
  }

  @Test
  void shouldThrowWhenProfileTypeIsUnknown() {
    CertificateAuthority ca =
        caManager.createAuthority("verifier-access-ca", "DIGG Wallet Verifier Access CA");
    KeyPair serviceKeyPair = keyGenerator.generateKeyPair();

    CertificateConfig config =
        CertificateConfigTestBuilder.builder()
            .id("custom-cert")
            .type("unknown-profile-type")
            .tradeName("Unknown")
            .build();

    assertThatThrownBy(() -> issuer.issueCertificate(config, serviceKeyPair.getPublic(), ca))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown certificate profile type: unknown-profile-type");
  }

  @Test
  void shouldThrowWhenSanHasInvalidIpAddress() {
    CertificateAuthority ca =
        caManager.createAuthority("verifier-access-ca", "DIGG Wallet Verifier Access CA");
    KeyPair serviceKeyPair = keyGenerator.generateKeyPair();

    CertificateConfig config =
        CertificateConfigTestBuilder.builder()
            .id("verifier-access-certificate")
            .type("relying-party-access")
            .tradeName("DIGG Verifier")
            .organizationIdentifier("VATSE-12345678")
            .sans(List.of("IP:not-an-ip-address"))
            .build();

    assertThatThrownBy(() -> issuer.issueCertificate(config, serviceKeyPair.getPublic(), ca))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Invalid IP address in SAN: not-an-ip-address");
  }
}
