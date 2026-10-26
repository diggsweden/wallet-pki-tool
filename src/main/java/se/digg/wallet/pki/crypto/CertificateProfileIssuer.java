// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;

/**
 * Issues service certificates according to the configured profiles for the wallet ecosystem.
 */
public final class CertificateProfileIssuer {

  public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
  public static final Duration DEFAULT_CERT_VALIDITY = Duration.ofDays(825);

  public static final ASN1ObjectIdentifier OID_POLICY_WRPAC =
      new ASN1ObjectIdentifier("0.4.0.194118.1.2");
  public static final ASN1ObjectIdentifier OID_POLICY_SERVICE =
      new ASN1ObjectIdentifier("0.4.0.2042.1.2");

  public static final ASN1ObjectIdentifier OID_QC_TYPE_PID =
      new ASN1ObjectIdentifier("0.4.0.194126.1.1");
  public static final ASN1ObjectIdentifier OID_QC_TYPE_WAL =
      new ASN1ObjectIdentifier("0.4.0.194126.1.2");
  public static final ASN1ObjectIdentifier OID_QC_TYPE_ESEAL =
      new ASN1ObjectIdentifier("0.4.0.1862.1.6.2");

  private final SecureRandom secureRandom;
  private final String caDistributionBaseUrl;

  public CertificateProfileIssuer() {
    this(new SecureRandom(), "http://trust-source");
  }

  public CertificateProfileIssuer(SecureRandom secureRandom) {
    this(secureRandom, "http://trust-source");
  }

  public CertificateProfileIssuer(SecureRandom secureRandom, String caDistributionBaseUrl) {
    this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom must not be null");
    this.caDistributionBaseUrl = se.digg.wallet.pki.domain.Checks
        .httpUrl(caDistributionBaseUrl, "caDistributionBaseUrl").replaceAll("/+$", "");
  }

  /**
   * Functional interface for applying profile-specific X.509 extensions.
   */
  @FunctionalInterface
  private interface ExtensionApplier {
    void apply(X509v3CertificateBuilder builder) throws IOException;
  }

  public X509Certificate issuePidSigningCertificate(CertificateSubject subject, PublicKey publicKey,
      CertificateAuthority authority) {
    return issueEudiServiceCertificate(subject, publicKey, authority, OID_QC_TYPE_PID);
  }

  public X509Certificate issueWalletSigningCertificate(CertificateSubject subject,
      PublicKey publicKey,
      CertificateAuthority authority) {
    return issueEudiServiceCertificate(subject, publicKey, authority, OID_QC_TYPE_WAL);
  }

  public X509Certificate issueRelyingPartyAccessCertificate(
      CertificateSubject certificateSubject,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa) {
    X500Name subject =
        buildSubjectDn(certificateSubject);
    String caName = signingCa.id();

    return issueCertificateInternal(
        subject,
        subjectPublicKey,
        signingCa,
        DEFAULT_CERT_VALIDITY,
        builder -> {
          builder.addExtension(
              Extension.keyUsage, true,
              new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
          addSubjectAlternativeNames(builder, certificateSubject.subjectAlternativeNames());
          addAiaAndCrlDistributionPoints(builder, caName);

          PolicyQualifierInfo cps =
              new PolicyQualifierInfo(caDistributionBaseUrl + "/" + caName + "/cps.md");
          PolicyInformation policyInfo =
              new PolicyInformation(OID_POLICY_WRPAC, new DERSequence(cps));
          builder.addExtension(
              Extension.certificatePolicies, false, new CertificatePolicies(policyInfo));
        });
  }

  public X509Certificate issueRelyingPartyRegistrationCertificate(
      CertificateSubject certificateSubject,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa) {
    X500Name subject =
        buildSubjectDn(certificateSubject);
    String caName = signingCa.id();

    return issueCertificateInternal(
        subject,
        subjectPublicKey,
        signingCa,
        DEFAULT_CERT_VALIDITY,
        builder -> {
          builder.addExtension(
              Extension.keyUsage, true,
              new KeyUsage(KeyUsage.digitalSignature));
          addSubjectAlternativeNames(builder, certificateSubject.subjectAlternativeNames());
          addAiaAndCrlDistributionPoints(builder, caName);
        });
  }

  private X509Certificate issueEudiServiceCertificate(
      CertificateSubject certificateSubject,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa, ASN1ObjectIdentifier qcType) {
    X500Name subject =
        buildSubjectDn(certificateSubject);
    String caName = signingCa.id();

    return issueCertificateInternal(
        subject,
        subjectPublicKey,
        signingCa,
        DEFAULT_CERT_VALIDITY,
        builder -> {
          builder.addExtension(
              Extension.keyUsage, true,
              new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
          builder.addExtension(
              Extension.extendedKeyUsage,
              false,
              new ExtendedKeyUsage(
                  new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth,
                      KeyPurposeId.id_kp_clientAuth}));
          addSubjectAlternativeNames(builder, certificateSubject.subjectAlternativeNames());
          addAiaAndCrlDistributionPoints(builder, caName);
          builder.addExtension(
              Extension.certificatePolicies,
              false,
              new CertificatePolicies(new PolicyInformation(OID_POLICY_SERVICE)));

          ASN1EncodableVector qcVector = new ASN1EncodableVector();
          qcVector.add(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance));
          qcVector.add(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType,
              new DERSequence(qcType)));
          builder.addExtension(Extension.qCStatements, false, new DERSequence(qcVector));
        });
  }

  public X509Certificate issueTrustSourceSignerCertificate(
      CertificateSubject certificateSubject,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa) {
    X500Name subject = buildSubjectDn(certificateSubject);

    return issueCertificateInternal(
        subject,
        subjectPublicKey,
        signingCa,
        DEFAULT_CERT_VALIDITY,
        builder -> {
          builder.addExtension(
              Extension.keyUsage, true,
              new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
          addSubjectAlternativeNames(builder, certificateSubject.subjectAlternativeNames());
          addCrlDistributionPoint(builder, signingCa.id());

          ASN1EncodableVector qcVector = new ASN1EncodableVector();
          qcVector.add(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance));
          qcVector.add(
              new QCStatement(
                  ETSIQCObjectIdentifiers.id_etsi_qcs_QcType,
                  new DERSequence(new ASN1ObjectIdentifier[] {OID_QC_TYPE_ESEAL})));
          builder.addExtension(Extension.qCStatements, false, new DERSequence(qcVector));
        });
  }

  public X509Certificate issueEncryptionCertificate(
      CertificateSubject certificateSubject,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa) {
    X500Name subject = buildSubjectDn(certificateSubject);

    return issueCertificateInternal(
        subject,
        subjectPublicKey,
        signingCa,
        DEFAULT_CERT_VALIDITY,
        builder -> {
          builder.addExtension(
              Extension.keyUsage,
              true,
              new KeyUsage(
                  KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement));
          builder.addExtension(
              Extension.extendedKeyUsage,
              false,
              new ExtendedKeyUsage(
                  new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth,
                      KeyPurposeId.id_kp_clientAuth}));
          addSubjectAlternativeNames(builder, certificateSubject.subjectAlternativeNames());
          addCrlDistributionPoint(builder, signingCa.id());
        });
  }

  private X509Certificate issueCertificateInternal(
      X500Name subject,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa,
      Duration validity,
      ExtensionApplier extensionApplier) {
    try {
      X509v3CertificateBuilder builder =
          createBaseBuilder(subject, subjectPublicKey, signingCa, validity);
      JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

      // Common extensions for all end-entity certificates
      builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
      builder.addExtension(
          Extension.subjectKeyIdentifier, false,
          extUtils.createSubjectKeyIdentifier(subjectPublicKey));
      builder.addExtension(
          Extension.authorityKeyIdentifier,
          false,
          extUtils.createAuthorityKeyIdentifier(signingCa.publicKey()));

      if (extensionApplier != null) {
        extensionApplier.apply(builder);
      }

      return signAndConvert(builder, signingCa);
    } catch (IOException | NoSuchAlgorithmException | OperatorCreationException
        | CertificateException e) {
      throw new PkiCryptoException("Failed to issue certificate for: " + subject, e);
    }
  }

  private X500Name buildSubjectDn(CertificateSubject subject) {
    return new X500NameBuilder(BCStyle.INSTANCE)
        .addRDN(BCStyle.CN, subject.commonName())
        .addRDN(BCStyle.O, subject.organization().name())
        .addRDN(BCStyle.C, subject.organization().country())
        .addRDN(BCStyle.ORGANIZATION_IDENTIFIER, subject.organization().identifier())
        .build();
  }

  private X509v3CertificateBuilder createBaseBuilder(
      X500Name subject,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa,
      Duration validity) {
    X500Name issuer =
        X500Name.getInstance(signingCa.certificate().getSubjectX500Principal().getEncoded());
    BigInteger serialNumber = new BigInteger(64, secureRandom).abs().add(BigInteger.ONE);
    Instant now = Instant.now().minus(Duration.ofMinutes(5));
    Date notBefore = Date.from(now);
    Date notAfter = Date.from(now.plus(validity));

    return new JcaX509v3CertificateBuilder(
        issuer, serialNumber, notBefore, notAfter, subject, subjectPublicKey);
  }

  private void addSubjectAlternativeNames(X509v3CertificateBuilder builder,
      SubjectAlternativeNames sans)
      throws IOException {
    List<GeneralName> names = new ArrayList<>();
    sans.dns().forEach(value -> names.add(new GeneralName(GeneralName.dNSName, value)));
    sans.ip().forEach(value -> names.add(new GeneralName(GeneralName.iPAddress, value)));
    sans.uri()
        .forEach(value -> names.add(new GeneralName(GeneralName.uniformResourceIdentifier, value)));
    if (!names.isEmpty()) {
      builder.addExtension(Extension.subjectAlternativeName, false,
          new GeneralNames(names.toArray(GeneralName[]::new)));
    }
  }

  private void addAiaAndCrlDistributionPoints(X509v3CertificateBuilder builder, String caName)
      throws IOException {
    addCrlDistributionPoint(builder, caName);

    String aiaUrl = caDistributionBaseUrl + "/" + caName + "/ca.pem";
    AccessDescription caIssuers =
        new AccessDescription(
            AccessDescription.id_ad_caIssuers,
            new GeneralName(GeneralName.uniformResourceIdentifier, aiaUrl));
    builder.addExtension(
        Extension.authorityInfoAccess, false, new AuthorityInformationAccess(caIssuers));
  }

  private void addCrlDistributionPoint(X509v3CertificateBuilder builder, String caName)
      throws IOException {
    String crlUrl = caDistributionBaseUrl + "/" + caName + "/revocation-list.pem";
    GeneralName crlName = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
    DistributionPointName dpn =
        new DistributionPointName(DistributionPointName.FULL_NAME, new GeneralNames(crlName));
    DistributionPoint dp = new DistributionPoint(dpn, null, null);
    builder.addExtension(
        Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {dp}));
  }

  private X509Certificate signAndConvert(
      X509v3CertificateBuilder builder, CertificateAuthority signingCa)
      throws OperatorCreationException, CertificateException {
    ContentSigner signer =
        new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(signingCa.privateKey());

    X509CertificateHolder holder = builder.build(signer);
    return new JcaX509CertificateConverter()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .getCertificate(holder);
  }
}
