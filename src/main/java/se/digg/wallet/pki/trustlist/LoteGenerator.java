// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Builds and serializes ETSI TS 119 602 List of Trusted Entities (LoTE) documents for wallet
 * ecosystem trust validation.
 */
public class LoteGenerator {

  public static final String LOTE_TYPE_WALLET_PROVIDERS =
      "http://uri.etsi.org/19602/LoTEType/wallet-providers";
  public static final String SVC_TYPE_WALLET_ISSUANCE =
      "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance";
  public static final String SVC_TYPE_PID_ISSUANCE =
      "http://uri.etsi.org/19602/SvcType/PID/Issuance";
  public static final String SVC_STATUS_GRANTED =
      "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";

  public static final String DEFAULT_SCHEME_OPERATOR = "DIGG";
  public static final String DEFAULT_SCHEME_NAME = "Local LoTE";
  public static final String DEFAULT_SCHEME_TERRITORY = "SE";
  public static final Duration DEFAULT_VALIDITY = Duration.ofDays(365);

  private final ObjectMapper objectMapper;
  private final TrustListSigner trustListSigner;

  /** Default constructor initializing Jackson ObjectMapper and TrustListSigner. */
  public LoteGenerator() {
    this(
        JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build(),
        new TrustListSigner());
  }

  /**
   * Constructor with explicit dependencies.
   *
   * @param objectMapper the Jackson object mapper
   * @param trustListSigner the trust list JWS signer
   */
  public LoteGenerator(ObjectMapper objectMapper, TrustListSigner trustListSigner) {
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    this.trustListSigner =
        Objects.requireNonNull(trustListSigner, "trustListSigner must not be null");
  }

  /**
   * Builds an ETSI TS 119 602 LoTE document from a list of entity certificates.
   *
   * @param certificates list of certificates to include in LoTE
   * @return populated LoteDocument
   */
  public LoteDocument buildLoteDocument(List<X509Certificate> certificates) {
    if (certificates == null || certificates.isEmpty()) {
      throw new IllegalArgumentException("certificates list must not be null or empty");
    }

    Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    Instant nextUpdate = now.plus(DEFAULT_VALIDITY);
    String issueDateTimeStr = now.toString();
    String nextUpdateStr = nextUpdate.toString();

    try {
      // 1. List and scheme metadata
      LoteDocument.ListAndSchemeInformation schemeInfo =
          new LoteDocument.ListAndSchemeInformation(
              1,
              1,
              LOTE_TYPE_WALLET_PROVIDERS,
              List.of(new LoteDocument.LangValue("en", DEFAULT_SCHEME_OPERATOR)),
              List.of(new LoteDocument.LangValue("en", DEFAULT_SCHEME_NAME)),
              DEFAULT_SCHEME_TERRITORY,
              issueDateTimeStr,
              nextUpdateStr);

      // 2. Trusted Entities generated dynamically from certificates
      List<LoteDocument.TrustedEntity> entities = new ArrayList<>();
      for (X509Certificate cert : certificates) {
        entities.add(createTrustedEntityFromCert(cert, issueDateTimeStr));
      }

      LoteDocument.LoteContent loteContent =
          new LoteDocument.LoteContent(schemeInfo, entities);

      return new LoteDocument(loteContent);
    } catch (CertificateEncodingException e) {
      throw new PkiCryptoException("Failed to encode certificates for LoTE document", e);
    }
  }

  /**
   * Builds an ETSI TS 119 602 LoTE document from Wallet Provider and PID Issuer certificates.
   *
   * @param walletProviderCert certificate of the Wallet Provider (CA or service cert)
   * @param pidIssuerCert certificate of the PID Issuer (CA or service cert)
   * @return populated LoteDocument
   */
  public LoteDocument buildLoteDocument(
      X509Certificate walletProviderCert, X509Certificate pidIssuerCert) {
    Objects.requireNonNull(walletProviderCert, "walletProviderCert must not be null");
    Objects.requireNonNull(pidIssuerCert, "pidIssuerCert must not be null");
    return buildLoteDocument(List.of(walletProviderCert, pidIssuerCert));
  }

  /**
   * Serializes a LoTE document to pretty-printed JSON string.
   *
   * @param loteDocument the document to serialize
   * @return JSON string
   */
  public String serializeLoteJson(LoteDocument loteDocument) {
    Objects.requireNonNull(loteDocument, "loteDocument must not be null");
    try {
      return objectMapper.writeValueAsString(loteDocument);
    } catch (JacksonException e) {
      throw new PkiCryptoException("Failed to serialize LoTE document to JSON", e);
    }
  }

  /**
   * Builds an ETSI TS 119 602 LoTE document from a list of certificates and signs it as a compact
   * JWS.
   *
   * @param certificates list of entity certificates
   * @param signingKey private key for signing
   * @param signingCert certificate of the signer (Trust Source)
   * @return signed compact JWS string
   */
  public String buildAndSignLote(
      List<X509Certificate> certificates,
      PrivateKey signingKey,
      X509Certificate signingCert) {
    LoteDocument doc = buildLoteDocument(certificates);
    String jsonPayload = serializeLoteJson(doc);
    return trustListSigner.signJws(jsonPayload, signingKey, signingCert);
  }

  /**
   * Builds an ETSI TS 119 602 LoTE document and signs it as a compact JWS token.
   *
   * @param walletProviderCert certificate of the Wallet Provider
   * @param pidIssuerCert certificate of the PID Issuer
   * @param signingKey private key for signing
   * @param signingCert certificate of the signer (Trust Source)
   * @return signed compact JWS string
   */
  public String buildAndSignLote(
      X509Certificate walletProviderCert,
      X509Certificate pidIssuerCert,
      PrivateKey signingKey,
      X509Certificate signingCert) {
    return buildAndSignLote(List.of(walletProviderCert, pidIssuerCert), signingKey, signingCert);
  }

  private LoteDocument.TrustedEntity createTrustedEntityFromCert(
      X509Certificate cert, String issueDateTimeStr) throws CertificateEncodingException {
    String certBase64 = Base64.getEncoder().encodeToString(cert.getEncoded());

    X500Name subject = new JcaX509CertificateHolder(cert).getSubject();

    RDN[] cns = subject.getRDNs(BCStyle.CN);
    String cn = cns.length > 0 ? IETFUtils.valueToString(cns[0].getFirst().getValue()) : null;

    RDN[] orgs = subject.getRDNs(BCStyle.O);
    String org = orgs.length > 0 ? IETFUtils.valueToString(orgs[0].getFirst().getValue()) : null;

    RDN[] countries = subject.getRDNs(BCStyle.C);
    String country =
        countries.length > 0
            ? IETFUtils.valueToString(countries[0].getFirst().getValue())
            : DEFAULT_SCHEME_TERRITORY;

    String entityName =
        cn != null && !cn.isBlank()
            ? cn
            : org != null && !org.isBlank() ? org : "Trusted Entity";
    String street =
        org != null && !org.isBlank()
            ? org
            : cn != null && !cn.isBlank() ? cn : "Local";

    List<String> uris = extractUris(cert);
    List<LoteDocument.UriValue> uriValues =
        uris.stream().map(u -> new LoteDocument.UriValue("en", u)).toList();

    LoteDocument.TeAddress address =
        new LoteDocument.TeAddress(
            List.of(new LoteDocument.PostalAddress("en", street, country)),
            uriValues);

    LoteDocument.TrustedEntityInformation entityInfo =
        new LoteDocument.TrustedEntityInformation(
            List.of(new LoteDocument.LangValue("en", entityName)),
            address,
            uriValues);

    LoteDocument.ServiceDigitalIdentity digitalIdentity =
        new LoteDocument.ServiceDigitalIdentity(
            List.of(new LoteDocument.X509CertificateVal(certBase64)));

    String serviceType = determineServiceType(cert, cn);
    String serviceName = entityName + " Issuance";

    LoteDocument.ServiceInformation serviceInfo =
        new LoteDocument.ServiceInformation(
            List.of(new LoteDocument.LangValue("en", serviceName)),
            digitalIdentity,
            serviceType,
            SVC_STATUS_GRANTED,
            issueDateTimeStr);

    LoteDocument.TrustedEntityService service =
        new LoteDocument.TrustedEntityService(serviceInfo);

    return new LoteDocument.TrustedEntity(entityInfo, List.of(service));
  }

  private List<String> extractUris(X509Certificate cert) {
    java.util.Set<String> uris = new java.util.LinkedHashSet<>();
    try {
      Collection<List<?>> sans = cert.getSubjectAlternativeNames();
      if (sans != null) {
        for (List<?> san : sans) {
          if (san.size() >= 2) {
            int type = ((Number) san.get(0)).intValue();
            Object val = san.get(1);
            if (type == 6 && val != null) { // URI
              uris.add(val.toString());
            } else if (type == 2 && val != null) { // DNS
              uris.add("https://" + val.toString());
            }
          }
        }
      }
    } catch (CertificateParsingException ignored) {
      // Fallback to default URI
    }
    if (uris.isEmpty()) {
      uris.add("http://localhost");
    }
    return new ArrayList<>(uris);
  }

  private String determineServiceType(X509Certificate cert, String cn) {
    byte[] qcExt = cert.getExtensionValue(Extension.qCStatements.getId());
    if (qcExt != null) {
      try {
        byte[] octets = ASN1OctetString.getInstance(qcExt).getOctets();
        ASN1Sequence qcSeq = ASN1Sequence.getInstance(octets);
        for (int i = 0; i < qcSeq.size(); i++) {
          QCStatement statement = QCStatement.getInstance(qcSeq.getObjectAt(i));
          if (ETSIQCObjectIdentifiers.id_etsi_qcs_QcType.equals(statement.getStatementId())
              && statement.getStatementInfo() instanceof ASN1Sequence typeSeq) {
            for (int j = 0; j < typeSeq.size(); j++) {
              ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) typeSeq.getObjectAt(j);
              if (new ASN1ObjectIdentifier("0.4.0.194126.1.1").equals(oid)) {
                return SVC_TYPE_PID_ISSUANCE;
              }
              if (new ASN1ObjectIdentifier("0.4.0.194126.1.2").equals(oid)) {
                return SVC_TYPE_WALLET_ISSUANCE;
              }
            }
          }
        }
      } catch (Exception ignored) {
        // Fallback to name heuristic
      }
    }

    if (cn != null) {
      String lower = cn.toLowerCase(Locale.ROOT);
      if (lower.contains("pid")) {
        return SVC_TYPE_PID_ISSUANCE;
      }
      if (lower.contains("wallet")) {
        return SVC_TYPE_WALLET_ISSUANCE;
      }
    }
    return SVC_TYPE_WALLET_ISSUANCE;
  }
}
