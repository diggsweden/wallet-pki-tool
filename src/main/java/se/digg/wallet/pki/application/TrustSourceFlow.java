// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import com.nimbusds.jose.JWSObject;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;
import se.digg.wallet.pki.domain.WalletRole;
import se.digg.wallet.pki.domain.WalletTrustAnchors;
import se.digg.wallet.pki.infrastructure.ArtifactWriter;
import se.digg.wallet.pki.infrastructure.EcosystemLayout;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.storage.ArtifactStore;
import se.digg.wallet.pki.trustlist.LoteGenerator;
import se.digg.wallet.pki.trustlist.RegistrationDocuments;
import se.digg.wallet.pki.trustlist.StatusListGenerator;

/** A dedicated signer owns the four-role LoTE and the sandbox's all-valid status list. */
final class TrustSourceFlow {
  static void provision(PkiConfiguration config, CertificateAuthority ca,
      WalletTrustAnchors anchors,
      EcosystemLayout layout, Clock clock, char[] password, boolean issue, boolean rotate)
      throws Exception {
    var stores = new IdentityStores(clock);
    if (issue) {
      var key = stores.keyPair(layout.trustSignerKeystore(), "trust_source", password, rotate);
      var issuer = new CertificateProfileIssuer(new java.security.SecureRandom(),
          config.publicationBaseUrl(), clock);
      var subject = new CertificateSubject(config.trustSource().signer().commonName(),
          config.organization(), SubjectAlternativeNames.empty());
      stores.write(WalletRole.TRUST_SOURCE,
          new SigningIdentity(key,
              issuer.issueTrustSourceSignerCertificate(subject, key.getPublic(), ca)),
          ca, layout, password);
    }
    var identity = stores.read(layout.trustSignerKeystore(), "trust_source", password);
    var writer = new ArtifactWriter();
    writer.pem(layout.trustSignerCertificate(), identity.certificate());
    var generator = new LoteGenerator();
    int sequence = Files.exists(layout.lote()) ? Math.addExact(lotePayload(layout).path("LoTE")
        .path("ListAndSchemeInformation").path("LoTESequenceNumber").asInt(), 1) : 1;
    Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
    var document =
        generator.buildLoteDocument(anchors, config.trustSource().lote(), config.organization(),
            now, expiry(config.trustSource().lote().validityDays(), identity.certificate(), now),
            sequence);
    writer.text(layout.lote(), generator.sign(document, identity));
    var status = config.trustSource().statusList();
    writer.text(layout.statusList(), new StatusListGenerator().buildAndSignStatusList(status.url(),
        StatusListGenerator.DEFAULT_EMPTY_STATUS_LIST, identity.keyPair().getPrivate(),
        identity.certificate(), now,
        Duration.between(now, expiry(status.validityDays(), identity.certificate(), now))));
  }

  static Instant documentsExpiry(EcosystemLayout layout) throws Exception {
    Instant lote = Instant.parse(lotePayload(layout).path("LoTE").path("ListAndSchemeInformation")
        .path("NextUpdate").asText());
    Instant status = RegistrationDocuments.expiresAt(layout.statusList());
    return lote.isBefore(status) ? lote : status;
  }

  static void verify(PkiConfiguration config, WalletTrustAnchors anchors,
      java.security.cert.X509Certificate certificate,
      EcosystemLayout layout, Clock clock) throws Exception {
    var verifier = new RegistrationDocuments(clock);
    var payload = verifier.verifyToken(layout.lote(), List.of(certificate), "trustlist+jwt");
    var info = payload.path("LoTE").path("ListAndSchemeInformation");
    Instant issue = Instant.parse(info.path("ListIssueDateTime").asText());
    int sequence = info.path("LoTESequenceNumber").asInt();
    Instant end = expiry(config.trustSource().lote().validityDays(), certificate, issue);
    if (sequence < 1 || issue.isAfter(clock.instant()) || !end.isAfter(clock.instant())) {
      throw new PkiCryptoException("LoTE is outside its validity period");
    }
    verifier.requirePayload(new LoteGenerator().buildLoteDocument(anchors,
        config.trustSource().lote(), config.organization(), issue, end, sequence), payload);
    var status = verifier.verifyToken(layout.statusList(), List.of(certificate), "statuslist+jwt");
    long issued = status.path("iat").asLong();
    var settings = config.trustSource().statusList();
    verifier.requirePayload(
        new StatusListGenerator.StatusListPayload(settings.url(), settings.url(), issued,
            expiry(settings.validityDays(), certificate, Instant.ofEpochSecond(issued))
                .getEpochSecond(),
            new StatusListGenerator.StatusListContent(1,
                StatusListGenerator.DEFAULT_EMPTY_STATUS_LIST)),
        status);
  }

  private static Instant expiry(int days, java.security.cert.X509Certificate certificate,
      Instant now) {
    Instant end = now.plus(Duration.ofDays(days));
    return end.isAfter(certificate.getNotAfter().toInstant())
        ? certificate.getNotAfter().toInstant()
        : end;
  }

  private static tools.jackson.databind.JsonNode lotePayload(EcosystemLayout layout)
      throws Exception {
    return ArtifactStore.JSON
        .readTree(JWSObject.parse(Files.readString(layout.lote())).getPayload().toString());
  }
}
