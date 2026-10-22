// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.generator;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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
import se.digg.wallet.pki.config.TrustListConfig;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.CertificateProfileType;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.crypto.KeystoreManager;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import se.digg.wallet.pki.trustlist.LoteGenerator;
import se.digg.wallet.pki.trustlist.StatusListGenerator;
import se.digg.wallet.pki.trustlist.TrustListSigner;

/**
 * Orchestrates generation and persistence of CAs, certificates, PKCS#12 keystores, and ETSI TS 119
 * 602 LoTE / Status List trust tokens.
 */
public class PkiEngine {

  private static final Logger log = LoggerFactory.getLogger(PkiEngine.class);
  private static final String TRUSTSTORE_FILENAME = "trusted_issuers.p12";

  private final EcKeyGenerator keyGenerator;
  private final CertificateAuthorityManager caManager;
  private final CertificateProfileIssuer issuer;
  private final KeystoreManager keystoreManager;
  private final SecretResolver secretResolver;
  private final LoteGenerator loteGenerator;
  private final StatusListGenerator statusListGenerator;
  private final TrustListSigner trustListSigner;

  /** Default constructor initializing all internal crypto components. */
  public PkiEngine() {
    this(new SecretResolver());
  }

  /** Creates a PkiEngine with a custom secret resolver. */
  public PkiEngine(SecretResolver secretResolver) {
    this(
        new EcKeyGenerator(),
        new CertificateAuthorityManager(),
        new CertificateProfileIssuer(),
        new KeystoreManager(),
        secretResolver,
        new LoteGenerator(),
        new StatusListGenerator(),
        new TrustListSigner());
  }

  /** Creates a PkiEngine with explicit dependencies. */
  public PkiEngine(
      EcKeyGenerator keyGenerator,
      CertificateAuthorityManager caManager,
      CertificateProfileIssuer issuer,
      KeystoreManager keystoreManager,
      SecretResolver secretResolver,
      LoteGenerator loteGenerator,
      StatusListGenerator statusListGenerator,
      TrustListSigner trustListSigner) {
    this.keyGenerator = Objects.requireNonNull(keyGenerator, "keyGenerator must not be null");
    this.caManager = Objects.requireNonNull(caManager, "caManager must not be null");
    this.issuer = Objects.requireNonNull(issuer, "issuer must not be null");
    this.keystoreManager =
        Objects.requireNonNull(keystoreManager, "keystoreManager must not be null");
    this.secretResolver = Objects.requireNonNull(secretResolver, "secretResolver must not be null");
    this.loteGenerator = Objects.requireNonNull(loteGenerator, "loteGenerator must not be null");
    this.statusListGenerator =
        Objects.requireNonNull(statusListGenerator, "statusListGenerator must not be null");
    this.trustListSigner =
        Objects.requireNonNull(trustListSigner, "trustListSigner must not be null");
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

    // Mirror CA certs and CRLs to ../trust-source if that directory exists
    Path trustSourceDir = baseOutputDir.resolve("../trust-source");
    if (Files.isDirectory(trustSourceDir)) {
      for (CertificateAuthority ca : caMap.values()) {
        try {
          Path caSubdir = trustSourceDir.resolve(ca.id());
          Files.createDirectories(caSubdir);
          keyGenerator.writePemFile(ca.certificate(), caSubdir.resolve("ca.pem"));
          if (ca.crl() != null) {
            keyGenerator.writePemFile(ca.crl(), caSubdir.resolve("revocation-list.pem"));
          }
          if (("trust-source".equals(ca.id()) || "trust-source-ca".equals(ca.id()))
              && ca.crl() != null) {
            keyGenerator.writePemFile(ca.crl(), trustSourceDir.resolve("revocation-list.pem"));
          }
        } catch (IOException e) {
          log.warn("Could not mirror CA '{}' to trust-source", ca.id(), e);
        }
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

      try {
        // Handle multi-key merged store for PID Issuer vs standard single-key store
        if (CertificateProfileType.PID_ISSUER_SERVICE.matches(certConfig.type())) {
          generatePidIssuerKeystore(
              certConfig, serviceKey, serviceCert, signingCa, p12Path, password,
              baseOutputDir);
        } else {
          String alias =
              certConfig.alias() != null && !certConfig.alias().isBlank()
                  ? certConfig.alias()
                  : certConfig.id().replace('-', '_');
          KeyStore keyStore =
              keystoreManager.createSingleKeyStore(
                  alias, serviceKey.getPrivate(), serviceCert, signingCa.certificate(), password);
          keystoreManager.saveKeyStore(keyStore, p12Path, password);

          if (CertificateProfileType.RELYING_PARTY_REGISTRATION.matches(certConfig.type())
              && certDir != null) {
            generateRegistrationCertificateJwt(serviceKey, serviceCert, signingCa, certDir);
          }
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

    CertificateAuthority pidCa =
        caMap.get("pid-issuer-ca") != null ? caMap.get("pid-issuer-ca") : caMap.get("pid-issuer");
    if (shouldUpdateTrustStore && pidCa != null) {
      X509Certificate pidIssuerCert =
          findCertificate("pid-issuer", issuedCerts, caMap, config, baseOutputDir);
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
                pidCa.certificate(),
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

    // 4. Generate Trust Lists (LoTE and Status Lists)
    if (config.trustLists() != null && !config.trustLists().isEmpty()) {
      for (TrustListConfig trustListConfig : config.trustLists()) {
        if (isSelective && !targets.contains(trustListConfig.id())) {
          continue;
        }

        CertificateAuthority signerCa = caMap.get(trustListConfig.signerAuthority());
        if (signerCa == null) {
          throw new PkiConfigurationException(
              "Trust list '%s' references unknown signer authority '%s'"
                  .formatted(trustListConfig.id(), trustListConfig.signerAuthority()));
        }

        Path outputPath = baseOutputDir.resolve(trustListConfig.outputFile());
        Path parentDir = outputPath.getParent();
        if (parentDir != null) {
          try {
            Files.createDirectories(parentDir);
          } catch (IOException e) {
            throw new PkiCryptoException(
                "Failed to create directory for trust list: " + parentDir, e);
          }
        }

        if (TrustListConfig.TYPE_LOTE.equals(trustListConfig.type())) {
          List<X509Certificate> loteCerts = new ArrayList<>();
          if (trustListConfig.entities() != null && !trustListConfig.entities().isEmpty()) {
            for (String entityId : trustListConfig.entities()) {
              X509Certificate cert =
                  findCertificate(entityId, issuedCerts, caMap, config, baseOutputDir);
              if (cert == null) {
                throw new PkiConfigurationException(
                    "Cannot generate LoTE: entity '%s' certificate not found"
                        .formatted(entityId));
              }
              loteCerts.add(cert);
            }
          } else {
            X509Certificate walletCert =
                findCertificate("wallet-provider-ca", issuedCerts, caMap, config, baseOutputDir);
            if (walletCert == null) {
              walletCert =
                  findCertificate("wallet-provider", issuedCerts, caMap, config, baseOutputDir);
            }
            X509Certificate pidCert =
                findCertificate("pid-issuer-ca", issuedCerts, caMap, config, baseOutputDir);
            if (pidCert == null) {
              pidCert =
                  findCertificate("pid-issuer", issuedCerts, caMap, config, baseOutputDir);
            }

            if (walletCert == null || pidCert == null) {
              throw new PkiConfigurationException(
                  "Cannot generate LoTE: missing wallet-provider or pid-issuer certificates");
            }
            loteCerts.add(walletCert);
            loteCerts.add(pidCert);
          }

          String signedLoteJws =
              loteGenerator.buildAndSignLote(
                  loteCerts, signerCa.privateKey(), signerCa.certificate());

          try {
            Files.writeString(outputPath, signedLoteJws, StandardCharsets.UTF_8);
          } catch (IOException e) {
            throw new PkiCryptoException("Failed to write LoTE JWS to: " + outputPath, e);
          }

          log.info("Trust list '{}' (ETSI TS 119 602) generated", trustListConfig.id());
          if (logger != null) {
            logger.println(
                "  ✓ Trust list '%s' (ETSI TS 119 602) generated".formatted(trustListConfig.id()));
          }
        } else if (TrustListConfig.TYPE_STATUS_LIST.equals(trustListConfig.type())) {
          Path fileNamePath = outputPath.getFileName();
          String fileName = fileNamePath != null ? fileNamePath.toString() : "status-list.jwt";
          String statusListUrl =
              (trustListConfig.url() != null && !trustListConfig.url().isBlank())
                  ? trustListConfig.url()
                  : "http://trust-source/signed/" + fileName;
          String signedStatusListJwt =
              statusListGenerator.buildAndSignStatusList(
                  statusListUrl,
                  null,
                  signerCa.privateKey(),
                  signerCa.certificate(),
                  null,
                  null);

          try {
            Files.writeString(outputPath, signedStatusListJwt, StandardCharsets.UTF_8);
          } catch (IOException e) {
            throw new PkiCryptoException(
                "Failed to write Status List JWT to: " + outputPath, e);
          }

          log.info("Status list '{}' (OAuth Status List) generated", trustListConfig.id());
          if (logger != null) {
            logger.println(
                "  ✓ Status list '%s' (OAuth Status List) generated"
                    .formatted(trustListConfig.id()));
          }
        } else {
          throw new PkiConfigurationException(
              "Unsupported trust list type '%s' for id '%s'"
                  .formatted(trustListConfig.type(), trustListConfig.id()));
        }
      }
    }
  }

  private X509Certificate findCertificate(
      String id,
      Map<String, X509Certificate> issuedCerts,
      Map<String, CertificateAuthority> caMap,
      PkiConfiguration config,
      Path baseOutputDir) {
    if (caMap != null && caMap.containsKey(id)) {
      return caMap.get(id).certificate();
    }
    if (issuedCerts != null && issuedCerts.containsKey(id)) {
      return issuedCerts.get(id);
    }
    if (config.certificates() != null) {
      CertificateConfig certConfig =
          config.certificates().stream()
              .filter(c -> id.equals(c.id()))
              .findFirst()
              .orElse(null);
      if (certConfig != null && certConfig.keystore() != null) {
        Path p12Path = baseOutputDir.resolve(certConfig.keystore());
        Path certDir = p12Path.getParent();
        if (certDir != null) {
          Path certPath = certDir.resolve("%s.crt".formatted(certConfig.id()));
          if (Files.exists(certPath)) {
            return caManager.readCertificatePem(certPath);
          }
        }
      }
    }
    if (config.authorities() != null) {
      AuthorityConfig authConfig =
          config.authorities().stream()
              .filter(a -> id.equals(a.id()))
              .findFirst()
              .orElse(null);
      if (authConfig != null) {
        Path caDir = baseOutputDir.resolve("ca");
        Path certPath =
            authConfig.certFile() != null
                ? baseOutputDir.resolve(authConfig.certFile())
                : caDir.resolve("%s.crt".formatted(authConfig.id()));
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
      Path p12Path,
      char[] password,
      Path baseOutputDir) {
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
    generatePidIssuerRegistrationJwt(serviceKey, serviceCert, baseOutputDir);
  }

  private void generatePidIssuerRegistrationJwt(
      KeyPair serviceKey, X509Certificate serviceCert, Path baseOutputDir) {
    Path pidIssuerDir = baseOutputDir.resolve("../pid-issuer");
    if (!Files.isDirectory(pidIssuerDir)) {
      return;
    }
    try {
      String payloadJson = "{\"iss\":\"did:web:localhost\",\"sub\":\"did:web:localhost\"}";
      String signedJwt =
          trustListSigner.signJws(payloadJson, serviceKey.getPrivate(), serviceCert, "rc-wrp+jwt");
      Files.writeString(
          pidIssuerDir.resolve("issuer_wrprc.jwt"), signedJwt, StandardCharsets.UTF_8);
      String certB64 = java.util.Base64.getEncoder().encodeToString(serviceCert.getEncoded());
      String preJwt =
          """
              {
                "headers": {"typ":"rc-wrp+jwt","alg":"ES256","x5c":["${certB64}"]},
                "payload": ${payloadJson}
              }"""
              .replace("${certB64}", certB64)
              .replace("${payloadJson}", payloadJson);
      Files.writeString(pidIssuerDir.resolve("issuer_wrprc.json"), preJwt, StandardCharsets.UTF_8);
    } catch (Exception e) {
      log.warn("Could not write PID issuer registration tokens to {}", pidIssuerDir, e);
    }
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

    log.info("Truststore '{}' generated", TRUSTSTORE_FILENAME);
    if (logger != null) {
      logger.println("  ✓ Truststore '%s' generated".formatted(TRUSTSTORE_FILENAME));
    }
  }

  /**
   * Generates local relying party registration certificate (WRPRC) JWT for the verifier backend.
   */
  private void generateRegistrationCertificateJwt(
      KeyPair keyPair,
      X509Certificate cert,
      CertificateAuthority signingCa,
      Path certDir) {
    long now = java.time.Instant.now().getEpochSecond();
    long exp = now + 31536000L;
    String payload =
        """
            {
              "name": "DIGG Wallet Ecosystem",
              "sub": "VATSE-12345678",
              "country": "SE",
              "iat": ${iat},
              "exp": ${exp},
              "registry_uri": "https://localhost/local-registration-certificate/registry",
              "srv_description": [
                {
                  "lang": "sv",
                  "value": "Lokal wallet-ekosystemtjänst"
                },
                {
                  "lang": "en",
                  "value": "Local wallet ecosystem service"
                }
              ],
              "entitlements": [
                "https://uri.etsi.org/19475/Entitlement/Service_Provider"
              ],
              "purpose": [
                {
                  "lang": "sv",
                  "value": "Identifiering med intyg"
                },
                {
                  "lang": "en",
                  "value": "Identification with credentials"
                }
              ],
              "credentials": [
                {
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": ["urn:eudi:pid:1"]
                  },
                  "claim": [
                    {"path": ["personal_administrative_number"]},
                    {"path": ["family_name"]},
                    {"path": ["given_name"]},
                    {"path": ["birthdate"]},
                    {"path": ["address", "street_address"]},
                    {"path": ["address", "postal_code"]},
                    {"path": ["address", "locality"]},
                    {"path": ["address", "country"]}
                  ]
                }
              ],
              "service_identifier": "wallet-ecosystem",
              "intended_use_id": "1",
              "privacy_policy": "https://localhost/local-registration-certificate/privacy",
              "info_uri": "https://localhost/local-registration-certificate/info",
              "support_uri": "https://localhost/local-registration-certificate/support",
              "supervisory_authority": {
                "name": "Local Wallet Ecosystem",
                "country": "SE",
                "email": "walletecosystem@example.com"
              },
              "policy_id": ["0.4.0.19475.3.1"],
              "certificate_policy": "https://localhost/local-registration-certificate/certificate-policy",
              "status": {
                "status_list": {
                  "uri": "https://localhost/local-registration-certificate/registration-certificate-status",
                  "idx": 0
                }
              }
            }
            """
            .replace("${iat}", String.valueOf(now))
            .replace("${exp}", String.valueOf(exp));

    try {
      String signedJwt =
          trustListSigner.signJws(
              payload,
              keyPair.getPrivate(),
              List.of(cert, signingCa.certificate()),
              "rc-wrp+jwt");
      Files.writeString(
          certDir.resolve("registration_certificate.jwt"), signedJwt, StandardCharsets.UTF_8);
      Files.writeString(
          certDir.resolve("registration_certificate.env"),
          "VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE=" + signedJwt + "\n",
          StandardCharsets.UTF_8);
    } catch (Exception e) {
      log.warn("Could not write registration_certificate tokens to {}", certDir, e);
    }
  }
}
