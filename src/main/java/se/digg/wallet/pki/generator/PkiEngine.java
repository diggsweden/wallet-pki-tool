// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.generator;

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.digg.wallet.pki.config.AuthorityConfig;
import se.digg.wallet.pki.config.CertificateConfig;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.PkiConfigurationException;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.CertificateProfileType;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.crypto.KeystoreManager;

/**
 * Orchestrates generation and persistence of CAs, certificates, and PKCS#12 keystores/truststores.
 */
public class PkiEngine {

  private static final Logger log = LoggerFactory.getLogger(PkiEngine.class);
  private static final String TRUSTSTORE_FILENAME = "trusted_issuers.p12";

  private final EcKeyGenerator keyGenerator;
  private final CertificateAuthorityManager caManager;
  private final CertificateProfileIssuer issuer;
  private final KeystoreManager keystoreManager;
  private final SecretResolver secretResolver;

  /** Default constructor initializing all internal crypto components. */
  public PkiEngine() {
    this(
        new EcKeyGenerator(),
        new CertificateAuthorityManager(),
        new CertificateProfileIssuer(),
        new KeystoreManager(),
        new SecretResolver());
  }

  /**
   * Constructor with explicit dependencies (useful for testing).
   *
   * @param keyGenerator EC key generator
   * @param caManager CA manager
   * @param issuer certificate profile issuer
   * @param keystoreManager keystore manager
   * @param secretResolver secret resolver
   */
  public PkiEngine(
      EcKeyGenerator keyGenerator,
      CertificateAuthorityManager caManager,
      CertificateProfileIssuer issuer,
      KeystoreManager keystoreManager,
      SecretResolver secretResolver) {
    this.keyGenerator = Objects.requireNonNull(keyGenerator, "keyGenerator must not be null");
    this.caManager = Objects.requireNonNull(caManager, "caManager must not be null");
    this.issuer = Objects.requireNonNull(issuer, "issuer must not be null");
    this.keystoreManager =
        Objects.requireNonNull(keystoreManager, "keystoreManager must not be null");
    this.secretResolver = Objects.requireNonNull(secretResolver, "secretResolver must not be null");
  }

  /**
   * Generates all configured PKI artifacts or a selected subset of targets.
   *
   * @param config the validated PKI configuration
   * @param targets optional list of target IDs to generate (null or empty generates all)
   */
  public void generate(PkiConfiguration config, List<String> targets) {
    generate(config, targets, null);
  }

  /**
   * Generates all configured PKI artifacts or a selected subset of targets.
   *
   * @param config the validated PKI configuration
   * @param targets optional list of target IDs to generate (null or empty generates all)
   * @param logger optional PrintWriter for status output (null suppresses output)
   */
  public void generate(PkiConfiguration config, List<String> targets, PrintWriter logger) {
    Objects.requireNonNull(config, "config must not be null");

    Path baseOutputDir = Path.of(config.outputDir());
    boolean isSelective = targets != null && !targets.isEmpty();

    // 1. Load or create all Certificate Authorities
    Map<String, CertificateAuthority> caMap = new HashMap<>();
    for (AuthorityConfig authConfig : config.authorities()) {
      CertificateAuthority ca = caManager.loadOrCreateAuthority(authConfig, baseOutputDir);
      caMap.put(authConfig.id(), ca);
      log.info("CA '{}' ({}) ready", authConfig.id(), authConfig.commonName());
      if (logger != null) {
        logger.println(
            "  ✓ CA '%s' (%s) ready".formatted(authConfig.id(), authConfig.commonName()));
      }
    }

    // 2. Generate certificates and keystores
    Map<String, X509Certificate> issuedCerts = new HashMap<>();

    for (CertificateConfig certConfig : config.certificates()) {
      if (isSelective && !targets.contains(certConfig.id())) {
        continue;
      }

      CertificateAuthority signingCa = caMap.get(certConfig.ca());
      if (signingCa == null) {
        throw new PkiConfigurationException(
            "Certificate '%s' references unknown authority '%s'"
                .formatted(certConfig.id(), certConfig.ca()));
      }

      String passwordStr = secretResolver.resolveKeystorePassword(certConfig);
      char[] password = passwordStr.toCharArray();

      Path p12Path = baseOutputDir.resolve(certConfig.keystore());
      Path certDir = p12Path.getParent();

      // Primary service key and certificate
      KeyPair serviceKey = keyGenerator.generateKeyPair();
      X509Certificate serviceCert =
          issuer.issueCertificate(certConfig, serviceKey.getPublic(), signingCa);
      issuedCerts.put(certConfig.id(), serviceCert);

      if (certDir != null) {
        keyGenerator.writePrivateKeyPem(
            serviceKey.getPrivate(), certDir.resolve("%s.key".formatted(certConfig.id())));
        keyGenerator.writePemFile(
            serviceCert, certDir.resolve("%s.crt".formatted(certConfig.id())));
      }

      try {
        // Handle multi-key merged store for PID Issuer vs standard single-key store
        if (CertificateProfileType.PID_ISSUER_SERVICE.matches(certConfig.type())) {
          generatePidIssuerKeystore(
              certConfig, serviceKey, serviceCert, signingCa, certDir, p12Path, password);
        } else {
          String alias = certConfig.id().replace('-', '_');
          KeyStore keyStore =
              keystoreManager.createSingleKeyStore(
                  alias, serviceKey.getPrivate(), serviceCert, signingCa.certificate(), password);
          keystoreManager.saveKeyStore(keyStore, p12Path, password);
        }
      } finally {
        // Zero out password array from memory immediately after keystore creation
        Arrays.fill(password, '\0');
      }

      log.info("Certificate and keystore '{}' generated", certConfig.id());
      if (logger != null) {
        logger.println(
            "  ✓ Certificate and keystore '%s' generated".formatted(certConfig.id()));
      }
    }

    // 3. Generate truststore if relevant (full generation, or when pid-issuer /
    // verifier-access-certificate are targeted)
    boolean shouldUpdateTrustStore =
        !isSelective
            || targets.contains("pid-issuer")
            || targets.contains("verifier-access-certificate");

    if (shouldUpdateTrustStore && caMap.containsKey("pid-issuer-ca")) {
      X509Certificate pidIssuerCert = findPidIssuerCertificate(issuedCerts, config, baseOutputDir);
      CertificateConfig verifierConfig =
          config.certificates().stream()
              .filter(c -> "verifier-access-certificate".equals(c.id()))
              .findFirst()
              .orElse(null);

      if (pidIssuerCert != null && verifierConfig != null) {
        char[] truststorePassword = null;
        try {
          truststorePassword =
              secretResolver.resolveKeystorePassword(verifierConfig).toCharArray();
        } catch (PkiConfigurationException e) {
          if (isSelective && !targets.contains("verifier-access-certificate")) {
            log.info(
                "Skipping truststore update: secret for 'verifier-access-certificate'"
                    + " not provided during selective rotation");
          } else {
            throw e;
          }
        }

        if (truststorePassword != null) {
          try {
            generateTrustStore(
                pidIssuerCert,
                caMap.get("pid-issuer-ca").certificate(),
                baseOutputDir,
                truststorePassword,
                logger);
          } finally {
            // Zero out password array from memory immediately after truststore creation
            Arrays.fill(truststorePassword, '\0');
          }
        }
      }
    }
  }

  private X509Certificate findPidIssuerCertificate(
      Map<String, X509Certificate> issuedCerts, PkiConfiguration config, Path baseOutputDir) {
    if (issuedCerts.containsKey("pid-issuer")) {
      return issuedCerts.get("pid-issuer");
    }
    CertificateConfig pidConfig =
        config.certificates().stream()
            .filter(c -> "pid-issuer".equals(c.id()))
            .findFirst()
            .orElse(null);
    if (pidConfig != null) {
      Path p12Path = baseOutputDir.resolve(pidConfig.keystore());
      Path certDir = p12Path.getParent();
      if (certDir != null) {
        Path certPath = certDir.resolve("%s.crt".formatted(pidConfig.id()));
        if (Files.exists(certPath)) {
          return caManager.readCertificatePem(certPath);
        }
      }
    }
    return null;
  }

  private void generatePidIssuerKeystore(
      CertificateConfig certConfig,
      KeyPair serviceKey,
      X509Certificate serviceCert,
      CertificateAuthority signingCa,
      Path certDir,
      Path p12Path,
      char[] password) {
    // Generate nonce-encryption key and certificate
    KeyPair nonceKey = keyGenerator.generateKeyPair();
    X509Certificate nonceCert =
        issuer.issueEncryptionCertificate(
            "nonce-encryption",
            certConfig.sans(),
            certConfig.country(),
            nonceKey.getPublic(),
            signingCa);

    // Generate request-encryption key and certificate
    KeyPair requestKey = keyGenerator.generateKeyPair();
    X509Certificate requestCert =
        issuer.issueEncryptionCertificate(
            "request-encryption",
            certConfig.sans(),
            certConfig.country(),
            requestKey.getPublic(),
            signingCa);

    if (certDir != null) {
      keyGenerator.writePrivateKeyPem(
          nonceKey.getPrivate(), certDir.resolve("nonce-encryption.key"));
      keyGenerator.writePemFile(nonceCert, certDir.resolve("nonce-encryption.crt"));
      keyGenerator.writePrivateKeyPem(
          requestKey.getPrivate(), certDir.resolve("request-encryption.key"));
      keyGenerator.writePemFile(requestCert, certDir.resolve("request-encryption.crt"));
    }

    // Build merged PKCS#12 keystore
    KeyStore keyStore = keystoreManager.createPkcs12KeyStore();
    keystoreManager.addKeyEntry(
        keyStore,
        "pid_issuer",
        serviceKey.getPrivate(),
        password,
        new Certificate[] {serviceCert, signingCa.certificate()});
    keystoreManager.addKeyEntry(
        keyStore,
        "nonce-encryption",
        nonceKey.getPrivate(),
        password,
        new Certificate[] {nonceCert, signingCa.certificate()});
    keystoreManager.addKeyEntry(
        keyStore,
        "request-encryption",
        requestKey.getPrivate(),
        password,
        new Certificate[] {requestCert, signingCa.certificate()});

    keystoreManager.saveKeyStore(keyStore, p12Path, password);
  }

  private void generateTrustStore(
      X509Certificate pidIssuerCert,
      X509Certificate pidIssuerCaCert,
      Path baseOutputDir,
      char[] password,
      PrintWriter logger) {
    KeyStore trustStore = keystoreManager.createPkcs12KeyStore();
    keystoreManager.addCertificateEntry(trustStore, "pid_issuer", pidIssuerCert);
    keystoreManager.addCertificateEntry(trustStore, "pid_issuer_ca", pidIssuerCaCert);

    Path trustStorePath = baseOutputDir.resolve(TRUSTSTORE_FILENAME);
    keystoreManager.saveKeyStore(trustStore, trustStorePath, password);

    Path verifierTrustStorePath =
        baseOutputDir.resolve("verifier-access-certificate").resolve(TRUSTSTORE_FILENAME);
    keystoreManager.saveKeyStore(trustStore, verifierTrustStorePath, password);

    log.info("Truststore '{}' generated", TRUSTSTORE_FILENAME);
    if (logger != null) {
      logger.println("  ✓ Truststore '%s' generated".formatted(TRUSTSTORE_FILENAME));
    }
  }
}
