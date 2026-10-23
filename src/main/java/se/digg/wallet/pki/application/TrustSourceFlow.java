// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

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
import se.digg.wallet.pki.infrastructure.ArtifactLayout;
import se.digg.wallet.pki.infrastructure.ArtifactWriter;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.trustlist.LoteGenerator;
import se.digg.wallet.pki.trustlist.RegistrationDocuments;
import se.digg.wallet.pki.trustlist.StatusListGenerator;

/** A dedicated signer owns the four-role LoTE and an all-valid test status list. */
final class TrustSourceFlow {
  static void generate(PkiConfiguration config, CertificateAuthority ca,
      WalletTrustAnchors anchors,
      ArtifactLayout layout, Clock clock, char[] password)
      throws Exception {
    var stores = new IdentityStores(clock);
    var key = new se.digg.wallet.pki.crypto.EcKeyGenerator().generateKeyPair();
    var issuer = new CertificateProfileIssuer(new java.security.SecureRandom(),
        config.publicationBaseUrl(), clock);
    var subject = new CertificateSubject(config.trustSource().signer().commonName(),
        config.organization(), SubjectAlternativeNames.empty());
    var identity = new SigningIdentity(key,
        issuer.issueTrustSourceSignerCertificate(subject, key.getPublic(), ca));
    stores.write(WalletRole.TRUST_SOURCE, identity, ca, layout, password);
    var writer = new ArtifactWriter();
    writer.pem(layout.trustSignerCertificate(), identity.certificate());
    var generator = new LoteGenerator();
    int sequence = config.trustSource().lote().sequenceNumber();
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

  static void verify(PkiConfiguration config, WalletTrustAnchors anchors,
      java.security.cert.X509Certificate certificate,
      ArtifactLayout layout, Clock clock) throws Exception {
    if (!certificate.equals(new se.digg.wallet.pki.crypto.CertificateAuthorityManager()
        .readCertificatePem(layout.trustSignerCertificate()))) {
      throw new PkiCryptoException("Exported trust signer differs from its keystore");
    }
    var verifier = new RegistrationDocuments(clock);
    var payload = verifier.verifyToken(layout.lote(), List.of(certificate), "trustlist+jwt");
    var info = payload.path("LoTE").path("ListAndSchemeInformation");
    Instant issue = Instant.parse(info.path("ListIssueDateTime").asText());
    int sequence = info.path("LoTESequenceNumber").asInt();
    Instant end = expiry(config.trustSource().lote().validityDays(), certificate, issue);
    if (sequence != config.trustSource().lote().sequenceNumber() || issue.isAfter(clock.instant())
        || !end.isAfter(clock.instant())) {
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

}
