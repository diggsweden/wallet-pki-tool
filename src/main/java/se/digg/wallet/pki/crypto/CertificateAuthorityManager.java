// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import java.io.IOException;
import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import se.digg.wallet.pki.domain.Organization;

/**
 * Manages creation, signing, serialization, and deserialization of Root Certificate Authorities
 * (CAs) and Certificate Revocation Lists (CRLs).
 */
public final class CertificateAuthorityManager {

  public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
  public static final Duration DEFAULT_CA_VALIDITY = Duration.ofDays(3650); // 10 years
  public static final String CA_CERT_FILENAME = "ca.pem";
  public static final String CA_KEY_FILENAME = "ca_private_key.pem";
  public static final String CRL_FILENAME = "revocation-list.pem";

  private final EcKeyGenerator keyGenerator = new EcKeyGenerator();
  private final SecureRandom secureRandom = new SecureRandom();

  /**
   * Creates a new Root Certificate Authority with generated key pair, self-signed cert, and empty
   * CRL.
   */
  public CertificateAuthority createAuthority(String id, String commonName) {
    return createAuthority(id, commonName, new Organization("DIGG", "SE", "VATSE-12345678"));
  }

  public CertificateAuthority createAuthority(String id, String commonName,
      Organization organization) {
    KeyPair keyPair = keyGenerator.generateKeyPair();
    X509Certificate certificate =
        generateRootCertificate(commonName, keyPair, DEFAULT_CA_VALIDITY, organization);
    X509CRL crl = generateEmptyCrl(certificate, keyPair, DEFAULT_CA_VALIDITY);
    return new CertificateAuthority(id, keyPair, certificate, crl);
  }

  /** Validates the supported root profile without needing access to its private key. */
  public void validateRootCertificate(X509Certificate certificate) {
    try {
      certificate.checkValidity();
      certificate.verify(certificate.getPublicKey());
      boolean[] usage = certificate.getKeyUsage();
      if (!certificate.getIssuerX500Principal().equals(certificate.getSubjectX500Principal())
          || certificate.getBasicConstraints() < 0 || usage == null || usage.length < 7
          || !usage[5] || !usage[6]) {
        throw new PkiCryptoException(
            "Expected a self-signed root CA with certificate and CRL signing usage");
      }
      if (!(certificate.getPublicKey() instanceof ECPublicKey ec)
          || !ec.getParams().getOrder()
              .equals(ECNamedCurveTable.getParameterSpec(EcKeyGenerator.DEFAULT_CURVE).getN())) {
        throw new PkiCryptoException("Wallet authorities require EC P-256 keys");
      }
    } catch (GeneralSecurityException e) {
      throw new PkiCryptoException("Invalid root authority certificate: " + e.getMessage(), e);
    }
  }

  /** Preserves and validates supplied revocation state rather than generating a replacement. */
  public void validateCrl(X509CRL crl, X509Certificate certificate) {
    try {
      crl.verify(certificate.getPublicKey());
      Date now = new Date();
      if (!crl.getIssuerX500Principal().equals(certificate.getSubjectX500Principal())
          || crl.getNextUpdate() == null || crl.getNextUpdate().before(now)
          || crl.getThisUpdate().after(now)) {
        throw new PkiCryptoException(
            "Authority CRL is expired, not yet valid or has a different issuer");
      }
    } catch (GeneralSecurityException e) {
      throw new PkiCryptoException("Invalid CRL signature", e);
    }
  }

  public void validateKeyPair(KeyPair keyPair, X509Certificate cert) {
    try {
      Signature sig =
          Signature.getInstance(SIGNATURE_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
      sig.initSign(keyPair.getPrivate(), secureRandom);
      byte[] challenge = "authority-key-validation-challenge".getBytes(StandardCharsets.UTF_8);
      sig.update(challenge);
      byte[] signature = sig.sign();

      sig.initVerify(cert.getPublicKey());
      sig.update(challenge);
      if (!sig.verify(signature)) {
        throw new PkiCryptoException(
            "Private key does not match the public key in certificate '%s'"
                .formatted(cert.getSubjectX500Principal().getName()));
      }
    } catch (GeneralSecurityException e) {
      throw new PkiCryptoException(
          "Failed to validate key pair against certificate: " + e.getMessage(), e);
    }
  }

  private X509Certificate generateRootCertificate(String commonName, KeyPair keyPair,
      Duration validity, Organization organization) {
    try {
      X500Name subjectAndIssuer =
          new X500NameBuilder(BCStyle.INSTANCE)
              .addRDN(BCStyle.CN, commonName)
              .addRDN(BCStyle.O, organization.name())
              .addRDN(BCStyle.C, organization.country())
              .build();

      BigInteger serialNumber =
          new BigInteger(64, secureRandom).abs().add(BigInteger.ONE);
      Instant now = Instant.now().minus(Duration.ofMinutes(5));
      Date notBefore = Date.from(now);
      Date notAfter = Date.from(now.plus(validity));

      X509v3CertificateBuilder certBuilder =
          new JcaX509v3CertificateBuilder(
              subjectAndIssuer, serialNumber, notBefore, notAfter, subjectAndIssuer,
              keyPair.getPublic());

      JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

      certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
      certBuilder.addExtension(
          Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
      certBuilder.addExtension(
          Extension.subjectKeyIdentifier, false,
          extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
      certBuilder.addExtension(
          Extension.authorityKeyIdentifier, false,
          extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));

      ContentSigner signer =
          new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
              .setProvider(BouncyCastleProvider.PROVIDER_NAME)
              .build(keyPair.getPrivate());

      X509CertificateHolder holder = certBuilder.build(signer);
      return new JcaX509CertificateConverter()
          .setProvider(BouncyCastleProvider.PROVIDER_NAME)
          .getCertificate(holder);

    } catch (IOException | NoSuchAlgorithmException | OperatorCreationException
        | CertificateException e) {
      throw new PkiCryptoException("Failed to generate Root CA certificate for: " + commonName, e);
    }
  }

  /** Generates a signed empty X.509 v2 CRL for the CA. */
  private X509CRL generateEmptyCrl(X509Certificate caCert, KeyPair keyPair, Duration validity) {
    try {
      Instant now = Instant.now().minus(Duration.ofMinutes(5));
      Date thisUpdate = Date.from(now);
      Date nextUpdate = Date.from(now.plus(validity));

      X509v2CRLBuilder crlBuilder =
          new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(), thisUpdate);
      crlBuilder.setNextUpdate(nextUpdate);

      JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

      crlBuilder.addExtension(
          Extension.authorityKeyIdentifier,
          false,
          extUtils.createAuthorityKeyIdentifier(caCert.getPublicKey()));
      crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));

      ContentSigner signer =
          new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
              .setProvider(BouncyCastleProvider.PROVIDER_NAME)
              .build(keyPair.getPrivate());

      X509CRLHolder crlHolder = crlBuilder.build(signer);
      return new JcaX509CRLConverter()
          .setProvider(BouncyCastleProvider.PROVIDER_NAME)
          .getCRL(crlHolder);

    } catch (IOException | NoSuchAlgorithmException | OperatorCreationException | CRLException e) {
      throw new PkiCryptoException(
          "Failed to generate empty CRL for CA: " + caCert.getSubjectX500Principal().getName(), e);
    }
  }

  /**
   * Saves the CA files (ca.pem, ca_private_key.pem, revocation-list.pem) to the target directory.
   */
  public void saveAuthority(CertificateAuthority ca, Path targetDir) {
    try {
      Files.createDirectories(targetDir);
      keyGenerator.writePrivateKeyPem(ca.privateKey(), targetDir.resolve(CA_KEY_FILENAME));
      keyGenerator.writePemFile(ca.certificate(), targetDir.resolve(CA_CERT_FILENAME));
      if (ca.crl() != null) {
        keyGenerator.writePemFile(ca.crl(), targetDir.resolve(CRL_FILENAME));
      }
    } catch (IOException e) {
      throw new PkiCryptoException("Failed to save CA files to: " + targetDir, e);
    }
  }

  /** Reads an X.509 Certificate from a PEM file. */
  public X509Certificate readCertificatePem(Path certPath) {
    try {
      if (!Files.exists(certPath)) {
        throw new PkiCryptoException("Certificate file not found: " + certPath);
      }
      String content = Files.readString(certPath, StandardCharsets.UTF_8);
      return readCertificatePem(content);
    } catch (IOException e) {
      throw new PkiCryptoException("Failed to read certificate file: " + certPath, e);
    }
  }

  /** Reads an X.509 Certificate from a PEM string. */
  public X509Certificate readCertificatePem(String pemContent) {
    try (PEMParser parser = new PEMParser(new StringReader(pemContent))) {
      Object parsed = parser.readObject();
      if (parsed == null) {
        throw new PkiCryptoException("No PEM object found in content");
      }
      if (parsed instanceof X509CertificateHolder holder) {
        return new JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(holder);
      } else {
        throw new PkiCryptoException(
            "Unsupported certificate format: " + parsed.getClass().getName());
      }
    } catch (IOException | CertificateException | RuntimeException e) {
      if (e instanceof PkiCryptoException pce) {
        throw pce;
      }
      throw new PkiCryptoException("Failed to parse X.509 Certificate from PEM", e);
    }
  }

  /** Reads an X.509 CRL from a PEM file. */
  public X509CRL readCrlPem(Path crlPath) {
    try {
      if (!Files.exists(crlPath)) {
        throw new PkiCryptoException("CRL file not found: " + crlPath);
      }
      String content = Files.readString(crlPath, StandardCharsets.UTF_8);
      return readCrlPem(content);
    } catch (IOException e) {
      throw new PkiCryptoException("Failed to read CRL file: " + crlPath, e);
    }
  }

  /** Reads an X.509 CRL from a PEM string. */
  public X509CRL readCrlPem(String pemContent) {
    try (PEMParser parser = new PEMParser(new StringReader(pemContent))) {
      Object parsed = parser.readObject();
      if (parsed == null) {
        throw new PkiCryptoException("No PEM object found in content");
      }
      if (parsed instanceof X509CRLHolder holder) {
        return new JcaX509CRLConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCRL(holder);
      } else {
        throw new PkiCryptoException("Unsupported CRL format: " + parsed.getClass().getName());
      }
    } catch (IOException | CRLException | RuntimeException e) {
      if (e instanceof PkiCryptoException pce) {
        throw pce;
      }
      throw new PkiCryptoException("Failed to parse X.509 CRL from PEM", e);
    }
  }
}
