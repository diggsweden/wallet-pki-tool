// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import se.digg.wallet.pki.config.LoteConfig;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.WalletTrustAnchors;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/** Builds LoTE entries from explicitly assigned wallet roles; certificates are never classified. */
public class LoteGenerator {
  public static final String LOTE_TYPE_WALLET_PROVIDERS =
      "http://uri.etsi.org/19602/LoTEType/wallet-providers";
  public static final String SVC_TYPE_WALLET_ISSUANCE =
      "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance";
  public static final String SVC_TYPE_PID_ISSUANCE =
      "http://uri.etsi.org/19602/SvcType/PID/Issuance";
  public static final String SVC_TYPE_WRPAC_ISSUANCE =
      "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance";
  public static final String SVC_TYPE_WRPRC_ISSUANCE =
      "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance";
  public static final String SVC_STATUS_GRANTED =
      "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
  private final ObjectMapper objectMapper;
  private final TrustListSigner trustListSigner;

  public LoteGenerator() {
    this(JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build(),
        new TrustListSigner());
  }

  public LoteGenerator(ObjectMapper objectMapper, TrustListSigner trustListSigner) {
    this.objectMapper = Objects.requireNonNull(objectMapper);
    this.trustListSigner = Objects.requireNonNull(trustListSigner);
  }

  public LoteDocument buildLoteDocument(WalletTrustAnchors anchors, LoteConfig config,
      Organization organization) {
    Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    var scheme = new LoteDocument.ListAndSchemeInformation(1, config.sequenceNumber(),
        LOTE_TYPE_WALLET_PROVIDERS,
        List.of(new LoteDocument.LangValue("en", organization.name())),
        List.of(new LoteDocument.LangValue("en", config.name())), organization.country(),
        now.toString(), now.plus(Duration.ofDays(config.validityDays())).toString());
    var entities = config.trustedAuthorities();
    return new LoteDocument(new LoteDocument.LoteContent(scheme, List.of(
        entity(anchors.walletProvider(), entities.walletProvider(), SVC_TYPE_WALLET_ISSUANCE,
            organization, now),
        entity(anchors.pidIssuer(), entities.pidIssuer(), SVC_TYPE_PID_ISSUANCE, organization, now),
        entity(anchors.verifierAccess(), entities.verifierAccess(), SVC_TYPE_WRPAC_ISSUANCE,
            organization, now),
        entity(anchors.verifierRegistration(), entities.verifierRegistration(),
            SVC_TYPE_WRPRC_ISSUANCE, organization, now))));
  }

  public String serializeLoteJson(LoteDocument document) {
    return objectMapper.writeValueAsString(document);
  }

  public String sign(LoteDocument document, SigningIdentity signer) {
    return trustListSigner.signJws(serializeLoteJson(document), signer.keyPair().getPrivate(),
        signer.certificate());
  }

  private LoteDocument.TrustedEntity entity(X509Certificate certificate, LoteConfig.Entity config,
      String serviceType, Organization organization, Instant issuedAt) {
    try {
      var uris = List.of(new LoteDocument.UriValue("en", config.informationUrl()));
      var address = new LoteDocument.TeAddress(List.of(
          new LoteDocument.PostalAddress("en", config.streetAddress(), organization.country())),
          uris);
      var information = new LoteDocument.TrustedEntityInformation(
          List.of(new LoteDocument.LangValue("en", config.entityName())), address, uris);
      var identity = new LoteDocument.ServiceDigitalIdentity(List.of(
          new LoteDocument.X509CertificateVal(
              Base64.getEncoder().encodeToString(certificate.getEncoded()))));
      var service = new LoteDocument.ServiceInformation(
          List.of(new LoteDocument.LangValue("en", config.serviceName())),
          identity, serviceType, SVC_STATUS_GRANTED, issuedAt.toString());
      return new LoteDocument.TrustedEntity(information,
          List.of(new LoteDocument.TrustedEntityService(service)));
    } catch (CertificateEncodingException e) {
      throw new PkiCryptoException("Cannot encode LoTE authority", e);
    }
  }
}
