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
import java.util.LinkedHashMap;
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

  public String buildLoteDocument(WalletTrustAnchors anchors, LoteConfig config,
      Organization organization) {
    Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    var authorities = config.trustedAuthorities();
    var entities = "[%s]".formatted(String.join(",\n",
        entity(anchors.walletProvider(), authorities.walletProvider(), SVC_TYPE_WALLET_ISSUANCE,
            organization, now),
        entity(anchors.pidIssuer(), authorities.pidIssuer(), SVC_TYPE_PID_ISSUANCE,
            organization, now),
        entity(anchors.verifierAccess(), authorities.verifierAccess(), SVC_TYPE_WRPAC_ISSUANCE,
            organization, now),
        entity(anchors.verifierRegistration(), authorities.verifierRegistration(),
            SVC_TYPE_WRPRC_ISSUANCE, organization, now)));
    var values = new LinkedHashMap<String, Object>();
    values.put("sequenceNumber", config.sequenceNumber());
    values.put("loteType", LOTE_TYPE_WALLET_PROVIDERS);
    values.put("operatorName", organization.name());
    values.put("schemeName", config.name());
    values.put("territory", organization.country());
    values.put("issuedAt", now.toString());
    values.put("nextUpdate", now.plus(Duration.ofDays(config.validityDays())).toString());

    return JsonTemplate.render(objectMapper, """
        {
          "LoTE": {
            "ListAndSchemeInformation": {
              "LoTEVersionIdentifier": 1,
              "LoTESequenceNumber": ${sequenceNumber},
              "LoTEType": ${loteType},
              "SchemeOperatorName": [{ "lang": "en", "value": ${operatorName} }],
              "SchemeName": [{ "lang": "en", "value": ${schemeName} }],
              "SchemeTerritory": ${territory},
              "ListIssueDateTime": ${issuedAt},
              "NextUpdate": ${nextUpdate}
            },
            "TrustedEntitiesList": ${entities}
          }
        }
        """, values).replace("${entities}", entities);
  }

  public String sign(String document, SigningIdentity signer) {
    return trustListSigner.signJws(document, signer.keyPair().getPrivate(),
        signer.certificate());
  }

  private String entity(X509Certificate certificate, LoteConfig.Entity config,
      String serviceType, Organization organization, Instant issuedAt) {
    try {
      var values = new LinkedHashMap<String, Object>();
      values.put("entityName", config.entityName());
      values.put("streetAddress", config.streetAddress());
      values.put("country", organization.country());
      values.put("informationUrl", config.informationUrl());
      values.put("serviceName", config.serviceName());
      values.put("certificate", Base64.getEncoder().encodeToString(certificate.getEncoded()));
      values.put("serviceType", serviceType);
      values.put("serviceStatus", SVC_STATUS_GRANTED);
      values.put("issuedAt", issuedAt.toString());

      return JsonTemplate.render(objectMapper, """
          {
            "TrustedEntityInformation": {
              "TEName": [{ "lang": "en", "value": ${entityName} }],
              "TEAddress": {
                "TEPostalAddress": [
                  { "lang": "en", "StreetAddress": ${streetAddress}, "Country": ${country} }
                ],
                "TEElectronicAddress": [{ "lang": "en", "uriValue": ${informationUrl} }]
              },
              "TEInformationURI": [{ "lang": "en", "uriValue": ${informationUrl} }]
            },
            "TrustedEntityServices": [
              {
                "ServiceInformation": {
                  "ServiceName": [{ "lang": "en", "value": ${serviceName} }],
                  "ServiceDigitalIdentity": {
                    "X509Certificates": [{ "val": ${certificate} }]
                  },
                  "ServiceTypeIdentifier": ${serviceType},
                  "ServiceStatus": ${serviceStatus},
                  "StatusStartingTime": ${issuedAt}
                }
              }
            ]
          }
          """, values);
    } catch (CertificateEncodingException e) {
      throw new PkiCryptoException("Cannot encode LoTE authority", e);
    }
  }
}
