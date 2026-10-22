// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.junit.jupiter.api.Test;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;

class CertificateProfileIssuerTest {
  private final CertificateProfileIssuer issuer =
      new CertificateProfileIssuer(new java.security.SecureRandom(), "https://publication.example");
  private final CertificateAuthority ca =
      new CertificateAuthorityManager().createAuthority("test", "Example CA");
  private final EcKeyGenerator keys = new EcKeyGenerator();
  private final CertificateSubject subject =
      new CertificateSubject("Example", new Organization("Example Org", "NO", "NTRNO-123"),
          new SubjectAlternativeNames(List.of("example.test"), List.of(ipv6Example()),
              List.of("https://example.test")));

  @Test
  void pid_and_wallet_signing_certificates_have_distinct_qc_types() throws Exception {
    var pid = issuer.issuePidSigningCertificate(subject, keys.generateKeyPair().getPublic(), ca);
    var wallet =
        issuer.issueWalletSigningCertificate(subject, keys.generateKeyPair().getPublic(), ca);
    assertThat(qcTypes(pid)).contains(CertificateProfileIssuer.OID_QC_TYPE_PID.getId())
        .doesNotContain(CertificateProfileIssuer.OID_QC_TYPE_WAL.getId());
    assertThat(qcTypes(wallet)).contains(CertificateProfileIssuer.OID_QC_TYPE_WAL.getId())
        .doesNotContain(CertificateProfileIssuer.OID_QC_TYPE_PID.getId());
    assertThat(pid.getSubjectX500Principal().getName()).contains("O=Example Org", "C=NO");
    assertLeaf(pid);
    assertLeaf(wallet);
  }

  @Test
  void access_certificates_have_policy_organization_and_explicit_san_types() throws Exception {
    var certificate =
        issuer.issueRelyingPartyAccessCertificate(subject, keys.generateKeyPair().getPublic(), ca);
    assertThat(certificate.getKeyUsage()[0]).isTrue();
    assertThat(certificate.getKeyUsage()[1]).isTrue();
    assertThat(certificate.getExtensionValue(Extension.certificatePolicies.getId())).isNotNull();
    assertThat(certificate.getSubjectAlternativeNames()).extracting(san -> (Integer) san.getFirst())
        .containsExactlyInAnyOrder(2, 7, 6);
    var aia = org.bouncycastle.asn1.x509.AuthorityInformationAccess.getInstance(ASN1OctetString
        .getInstance(certificate.getExtensionValue(Extension.authorityInfoAccess.getId()))
        .getOctets());
    assertThat(aia.getAccessDescriptions()[0].getAccessLocation().getName().toString())
        .isEqualTo("https://publication.example/test/ca.pem");
    assertLeaf(certificate);
  }

  @Test
  void registration_signers_use_digital_signature_usage() throws Exception {
    var certificate = issuer.issueRelyingPartyRegistrationCertificate(subject,
        keys.generateKeyPair().getPublic(), ca);
    assertThat(certificate.getKeyUsage()[0]).isTrue();
    assertLeaf(certificate);
  }

  @Test
  void trust_source_signers_are_leaf_certificates_with_eseal_qc_type() throws Exception {
    var certificate =
        issuer.issueTrustSourceSignerCertificate(subject, keys.generateKeyPair().getPublic(), ca);
    assertThat(qcTypes(certificate)).contains(CertificateProfileIssuer.OID_QC_TYPE_ESEAL.getId());
    assertLeaf(certificate);
  }

  @Test
  void encryption_certificates_have_encryption_and_agreement_usage() throws Exception {
    var certificate =
        issuer.issueEncryptionCertificate(subject, keys.generateKeyPair().getPublic(), ca);
    assertThat(certificate.getKeyUsage()[2]).isTrue();
    assertThat(certificate.getKeyUsage()[3]).isTrue();
    assertThat(certificate.getKeyUsage()[4]).isTrue();
    assertThat(certificate.getKeyUsage()[0]).isFalse();
    assertLeaf(certificate);
  }

  @Test
  void invalid_sans_and_missing_organization_identifiers_are_rejected_at_construction() {
    assertThatThrownBy(() -> new SubjectAlternativeNames(null, List.of("invalid-ip"), null))
        .hasMessageContaining("Invalid IP SAN");
    assertThatThrownBy(
        () -> new SubjectAlternativeNames(List.of("https://example.test"), null, null))
        .hasMessageContaining("Invalid DNS SAN");
    assertThatThrownBy(() -> new SubjectAlternativeNames(null, null, List.of("relative")))
        .hasMessageContaining("absolute");
    assertThatThrownBy(() -> new Organization("Example", "SE", ""))
        .hasMessageContaining("identifier");
  }

  @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
  private String ipv6Example() {
    return "2001:db8::1";
  }

  private void assertLeaf(X509Certificate certificate) throws Exception {
    certificate.verify(ca.publicKey());
    certificate.checkValidity();
    assertThat(certificate.getBasicConstraints()).isEqualTo(-1);
  }

  private List<String> qcTypes(X509Certificate certificate) {
    var sequence = ASN1Sequence.getInstance(ASN1OctetString
        .getInstance(certificate.getExtensionValue(Extension.qCStatements.getId())).getOctets());
    var types = new java.util.ArrayList<String>();
    for (var value : sequence) {
      var statement = QCStatement.getInstance(value);
      if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.equals(statement.getStatementId())) {
        for (var type : ASN1Sequence.getInstance(statement.getStatementInfo()))
          types.add(type.toString());
      }
    }
    return types;
  }
}
