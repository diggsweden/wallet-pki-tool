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
import java.util.regex.Pattern;
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
import se.digg.wallet.pki.config.CertificateConfig;

/**
 * Issues service certificates according to the configured profiles for the wallet ecosystem.
 */
public class CertificateProfileIssuer {

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

  public CertificateProfileIssuer() {
    this(new SecureRandom());
  }

  public CertificateProfileIssuer(SecureRandom secureRandom) {
    this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom must not be null");
  }

  /**
   * Functional interface for applying profile-specific X.509 extensions.
   */
  @FunctionalInterface
  private interface ExtensionApplier {
    void apply(X509v3CertificateBuilder builder) throws IOException;
  }

  /**
   * Issues a certificate based on the requested profile type.
   */
  public X509Certificate issueCertificate(
      CertificateConfig certConfig, PublicKey subjectPublicKey, CertificateAuthority signingCa) {
    Objects.requireNonNull(certConfig, "certConfig must not be null");
    Objects.requireNonNull(subjectPublicKey, "subjectPublicKey must not be null");
    Objects.requireNonNull(signingCa, "signingCa must not be null");

    CertificateProfileType profileType = CertificateProfileType.fromString(certConfig.type());
    String commonName =
        certConfig.tradeName() != null && !certConfig.tradeName().isBlank()
            ? certConfig.tradeName()
            : certConfig.id();

    return switch (profileType) {
      case RELYING_PARTY_ACCESS -> issueRelyingPartyAccessCertificate(
          certConfig, commonName, subjectPublicKey, signingCa);
      case PID_ISSUER_SERVICE, WALLET_PROVIDER_SERVICE -> issueEudiServiceCertificate(
          certConfig, commonName, subjectPublicKey, signingCa);
      case TRUST_SOURCE_SIGNER -> issueTrustSourceSignerCertificate(
          certConfig, commonName, subjectPublicKey, signingCa);
      case ENCRYPTION -> issueEncryptionCertificate(
          commonName, certConfig.sans(), certConfig.country(), subjectPublicKey, signingCa);
      case GENERIC_SERVICE -> issueGenericServiceCertificate(
          certConfig, commonName, subjectPublicKey, signingCa);
    };
  }

  public X509Certificate issueRelyingPartyAccessCertificate(
      CertificateConfig certConfig,
      String commonName,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa) {
    if (certConfig.organizationIdentifier() == null
        || certConfig.organizationIdentifier().isBlank()) {
      throw new PkiCryptoException(
          ("Certificate '%s' of type 'relying-party-access' requires a non-blank"
              + " 'organizationIdentifier' according to ETSI TS 119 411-8")
              .formatted(certConfig.id()));
    }

    X500Name subject =
        buildSubjectDn(commonName, certConfig.country(), certConfig.organizationIdentifier());
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
                  new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth,
                      KeyPurposeId.id_kp_serverAuth}));
          addSubjectAlternativeNames(builder, certConfig.sans());
          addAiaAndCrlDistributionPoints(builder, caName);

          PolicyQualifierInfo cps =
              new PolicyQualifierInfo("http://trust-source/%s/cps.md".formatted(caName));
          PolicyInformation policyInfo =
              new PolicyInformation(OID_POLICY_WRPAC, new DERSequence(cps));
          builder.addExtension(
              Extension.certificatePolicies, false, new CertificatePolicies(policyInfo));
        });
  }

  public X509Certificate issueEudiServiceCertificate(
      CertificateConfig certConfig,
      String commonName,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa) {
    X500Name subject =
        buildSubjectDn(commonName, certConfig.country(), certConfig.organizationIdentifier());
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
          addSubjectAlternativeNames(builder, certConfig.sans());
          addAiaAndCrlDistributionPoints(builder, caName);
          builder.addExtension(
              Extension.certificatePolicies,
              false,
              new CertificatePolicies(new PolicyInformation(OID_POLICY_SERVICE)));

          ASN1EncodableVector qcVector = new ASN1EncodableVector();
          qcVector.add(new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcCompliance));
          qcVector.add(
              new QCStatement(
                  ETSIQCObjectIdentifiers.id_etsi_qcs_QcType,
                  new DERSequence(new ASN1ObjectIdentifier[] {OID_QC_TYPE_PID})));
          qcVector.add(
              new QCStatement(
                  ETSIQCObjectIdentifiers.id_etsi_qcs_QcType,
                  new DERSequence(new ASN1ObjectIdentifier[] {OID_QC_TYPE_WAL})));
          builder.addExtension(Extension.qCStatements, false, new DERSequence(qcVector));
        });
  }

  public X509Certificate issueTrustSourceSignerCertificate(
      CertificateConfig certConfig,
      String commonName,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa) {
    X500Name subject = buildSubjectDn(commonName, certConfig.country(), null);

    return issueCertificateInternal(
        subject,
        subjectPublicKey,
        signingCa,
        DEFAULT_CERT_VALIDITY,
        builder -> {
          builder.addExtension(
              Extension.keyUsage, true,
              new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
          addSubjectAlternativeNames(builder, certConfig.sans());
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
      String commonName,
      List<String> sans,
      String country,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa) {
    X500Name subject = buildSubjectDn(commonName, country, null);

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
          addSubjectAlternativeNames(builder, sans);
          addCrlDistributionPoint(builder, signingCa.id());
        });
  }

  public X509Certificate issueGenericServiceCertificate(
      CertificateConfig certConfig,
      String commonName,
      PublicKey subjectPublicKey,
      CertificateAuthority signingCa) {
    X500Name subject = buildSubjectDn(commonName, certConfig.country(), null);

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
          addSubjectAlternativeNames(builder, certConfig.sans());
          addAiaAndCrlDistributionPoints(builder, signingCa.id());
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

  private X500Name buildSubjectDn(String commonName, String country, String orgIdentifier) {
    X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
    builder.addRDN(BCStyle.CN, commonName);
    builder.addRDN(BCStyle.O, "DIGG");
    builder.addRDN(BCStyle.C, country != null && !country.isBlank() ? country : "SE");
    if (orgIdentifier != null && !orgIdentifier.isBlank()) {
      builder.addRDN(BCStyle.ORGANIZATION_IDENTIFIER, orgIdentifier);
    } else if (orgIdentifier != null) {
      builder.addRDN(BCStyle.ORGANIZATION_IDENTIFIER, "VATSE-12345678");
    }
    return builder.build();
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

  private void addSubjectAlternativeNames(X509v3CertificateBuilder builder, List<String> sans)
      throws IOException {
    if (sans == null || sans.isEmpty()) {
      return;
    }

    List<GeneralName> names = new ArrayList<>();
    for (String san : sans) {
      names.add(parseGeneralName(san));
    }
    builder.addExtension(
        Extension.subjectAlternativeName,
        false,
        new GeneralNames(names.toArray(new GeneralName[0])));
  }

  private static final Pattern IPV4_PATTERN =
      Pattern.compile("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$");
  private static final Pattern IPV6_PATTERN =
      Pattern.compile(
          "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::$|^::1$|"
              + "^([0-9a-fA-F]{1,4}:)+[0-9a-fA-F]{1,4}$");

  /**
   * Parses a Subject Alternative Name (SAN) string and auto-detects URI, IP address, or DNS name if
   * explicit prefixes (such as "DNS:", "IP:", "URI:") are omitted.
   */
  private GeneralName parseGeneralName(String san) {
    String trimmed = san.trim();
    if (trimmed.regionMatches(true, 0, "DNS:", 0, 4)) {
      return new GeneralName(GeneralName.dNSName, trimmed.substring(4).trim());
    }
    if (trimmed.regionMatches(true, 0, "IP:", 0, 3)) {
      String ip = trimmed.substring(3).trim();
      if (!IPV4_PATTERN.matcher(ip).matches() && !IPV6_PATTERN.matcher(ip).matches()) {
        throw new PkiCryptoException("Invalid IP address in SAN: " + ip);
      }
      return new GeneralName(GeneralName.iPAddress, ip);
    }
    if (trimmed.regionMatches(true, 0, "URI:", 0, 4)) {
      return new GeneralName(GeneralName.uniformResourceIdentifier, trimmed.substring(4).trim());
    }
    if (trimmed.regionMatches(true, 0, "http://", 0, 7)
        || trimmed.regionMatches(true, 0, "https://", 0, 8)
        || trimmed.contains("://")) {
      return new GeneralName(GeneralName.uniformResourceIdentifier, trimmed);
    }
    if (IPV4_PATTERN.matcher(trimmed).matches() || IPV6_PATTERN.matcher(trimmed).matches()) {
      return new GeneralName(GeneralName.iPAddress, trimmed);
    }
    return new GeneralName(GeneralName.dNSName, trimmed);
  }

  private void addAiaAndCrlDistributionPoints(X509v3CertificateBuilder builder, String caName)
      throws IOException {
    addCrlDistributionPoint(builder, caName);

    String aiaUrl = "http://trust-source/%s/ca.pem".formatted(caName);
    AccessDescription caIssuers =
        new AccessDescription(
            AccessDescription.id_ad_caIssuers,
            new GeneralName(GeneralName.uniformResourceIdentifier, aiaUrl));
    builder.addExtension(
        Extension.authorityInfoAccess, false, new AuthorityInformationAccess(caIssuers));
  }

  private void addCrlDistributionPoint(X509v3CertificateBuilder builder, String caName)
      throws IOException {
    String crlUrl = "http://trust-source/%s/revocation-list.pem".formatted(caName);
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
