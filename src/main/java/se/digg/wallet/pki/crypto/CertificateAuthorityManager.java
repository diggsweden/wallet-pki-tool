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
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import se.digg.wallet.pki.config.AuthorityConfig;

/**
 * Manages creation, signing, serialization, and deserialization of Root Certificate Authorities
 * (CAs) and Certificate Revocation Lists (CRLs).
 */
public class CertificateAuthorityManager {

  public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
  public static final Duration DEFAULT_CA_VALIDITY = Duration.ofDays(3650); // 10 years
  public static final String CA_CERT_FILENAME = "ca.pem";
  public static final String CA_KEY_FILENAME = "ca_private_key.pem";
  public static final String CRL_FILENAME = "revocation-list.pem";

  private final EcKeyGenerator keyGenerator;
  private final SecureRandom secureRandom;

  /** Default constructor. */
  public CertificateAuthorityManager() {
    this(new EcKeyGenerator(), new SecureRandom());
  }

  /**
   * Constructor with explicit dependencies.
   *
   * @param keyGenerator the EC key generator
   * @param secureRandom the secure random generator
   */
  public CertificateAuthorityManager(EcKeyGenerator keyGenerator, SecureRandom secureRandom) {
    this.keyGenerator = Objects.requireNonNull(keyGenerator, "keyGenerator must not be null");
    this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom must not be null");
  }

  /**
   * Creates a new Root Certificate Authority with generated key pair, self-signed cert, and empty
   * CRL.
   *
   * @param id authority unique identifier
   * @param commonName the Subject Common Name (CN)
   * @return the newly created CertificateAuthority
   */
  public CertificateAuthority createAuthority(String id, String commonName) {
    KeyPair keyPair = keyGenerator.generateKeyPair();
    X509Certificate certificate =
        generateRootCertificate(commonName, keyPair, DEFAULT_CA_VALIDITY);
    X509CRL crl = generateEmptyCrl(certificate, keyPair, DEFAULT_CA_VALIDITY);
    return new CertificateAuthority(id, keyPair, certificate, crl);
  }

  /**
   * Loads an existing Authority or generates a new one based on the configuration and directory.
   *
   * @param config the Authority configuration
   * @param baseOutputDir base directory for outputs (e.g. ./config/certificates)
   * @return loaded or generated CertificateAuthority
   */
  public CertificateAuthority loadOrCreateAuthority(AuthorityConfig config, Path baseOutputDir) {
    if (config == null) {
      throw new PkiCryptoException("AuthorityConfig must not be null");
    }

    // 1. Check if external keyFile and certFile are configured
    if (config.keyFile() != null && config.certFile() != null) {
      Path keyPath = Path.of(config.keyFile());
      Path certPath = Path.of(config.certFile());
      PrivateKey privateKey = keyGenerator.readPrivateKeyPem(keyPath);
      X509Certificate cert = readCertificatePem(certPath);
      KeyPair keyPair = new KeyPair(cert.getPublicKey(), privateKey);
      validateAuthority(keyPair, cert);
      X509CRL crl = generateEmptyCrl(cert, keyPair, DEFAULT_CA_VALIDITY);
      return new CertificateAuthority(config.id(), keyPair, cert, crl);
    }
    if (config.keyFile() != null || config.certFile() != null) {
      throw new PkiCryptoException(
          "Both 'keyFile' and 'certFile' must be provided when configuring external CA for"
              + " authority: %s"
                  .formatted(config.id()));
    }

    // 2. Check if CA files already exist in standard output directory: <baseOutputDir>/ca/<id>/
    Path caDir = baseOutputDir.resolve("ca").resolve(config.id());
    Path caKeyFile = caDir.resolve(CA_KEY_FILENAME);
    Path caCertFile = caDir.resolve(CA_CERT_FILENAME);
    Path crlFile = caDir.resolve(CRL_FILENAME);

    boolean keyExists = Files.exists(caKeyFile);
    boolean certExists = Files.exists(caCertFile);

    if (keyExists && certExists) {
      PrivateKey privateKey = keyGenerator.readPrivateKeyPem(caKeyFile);
      X509Certificate cert = readCertificatePem(caCertFile);
      KeyPair keyPair = new KeyPair(cert.getPublicKey(), privateKey);
      validateAuthority(keyPair, cert);
      X509CRL crl = Files.exists(crlFile) ? readCrlPem(crlFile)
          : generateEmptyCrl(cert, keyPair, DEFAULT_CA_VALIDITY);
      return new CertificateAuthority(config.id(), keyPair, cert, crl);
    }

    // Reject incomplete CA state to avoid silently overwriting surviving trust anchor material
    if (keyExists || certExists) {
      throw new PkiCryptoException(
          ("Incomplete CA files found in %s (key exists: %b, cert exists: %b)."
              + " Refusing to overwrite existing material without explicit rotation.")
              .formatted(caDir, keyExists, certExists));
    }

    // 3. Generate new CA and save to disk
    CertificateAuthority ca = createAuthority(config.id(), config.commonName());
    saveAuthority(ca, caDir);
    return ca;
  }

  /**
   * Validates that a CA certificate is valid, has CA basic constraints, and matches its private
   * key.
   *
   * @param keyPair the CA key pair
   * @param cert the CA certificate
   * @throws PkiCryptoException if validation fails
   */
  public void validateAuthority(KeyPair keyPair, X509Certificate cert) {
    Objects.requireNonNull(keyPair, "keyPair must not be null");
    Objects.requireNonNull(cert, "cert must not be null");

    try {
      cert.checkValidity();
    } catch (CertificateException e) {
      throw new PkiCryptoException("CA certificate is not valid: " + e.getMessage(), e);
    }

    if (cert.getBasicConstraints() < 0) {
      throw new PkiCryptoException(
          "Certificate '%s' is not a valid Certificate Authority (basicConstraints cA is not true)"
              .formatted(cert.getSubjectX500Principal().getName()));
    }

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
            "Private key does not match the public key in CA certificate '%s'"
                .formatted(cert.getSubjectX500Principal().getName()));
      }
    } catch (Exception e) {
      throw new PkiCryptoException(
          "Failed to validate CA key pair against certificate: " + e.getMessage(), e);
    }
  }

  /**
   * Generates a self-signed X.509 v3 Root CA Certificate.
   *
   * @param commonName the Subject Common Name
   * @param keyPair the key pair used for signing and subject
   * @param validity validity duration
   * @return generated X509Certificate
   */
  public X509Certificate generateRootCertificate(
      String commonName, KeyPair keyPair, Duration validity) {
    try {
      X500Name subjectAndIssuer =
          new X500NameBuilder(BCStyle.INSTANCE)
              .addRDN(BCStyle.CN, commonName)
              .addRDN(BCStyle.O, "DIGG")
              .addRDN(BCStyle.C, "SE")
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

  /**
   * Generates a signed empty X.509 v2 CRL for the CA.
   *
   * @param caCert the CA certificate
   * @param keyPair the CA key pair
   * @param validity validity duration for the CRL
   * @return generated X509CRL
   */
  public X509CRL generateEmptyCrl(X509Certificate caCert, KeyPair keyPair, Duration validity) {
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
   *
   * @param ca the CertificateAuthority to save
   * @param targetDir destination directory
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

  /**
   * Reads an X.509 Certificate from a PEM file.
   *
   * @param certPath path to the PEM file
   * @return the parsed X509Certificate
   */
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

  /**
   * Reads an X.509 Certificate from a PEM string.
   *
   * @param pemContent the PEM string content
   * @return the parsed X509Certificate
   */
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

  /**
   * Reads an X.509 CRL from a PEM file.
   *
   * @param crlPath path to the CRL file
   * @return the parsed X509CRL
   */
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

  /**
   * Reads an X.509 CRL from a PEM string.
   *
   * @param pemContent the PEM string content
   * @return the parsed X509CRL
   */
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
