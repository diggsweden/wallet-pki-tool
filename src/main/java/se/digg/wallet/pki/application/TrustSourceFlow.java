// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.time.Duration;
import java.time.Instant;
import se.digg.wallet.pki.config.TrustSourceConfig;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;
import se.digg.wallet.pki.domain.WalletTrustAnchors;
import se.digg.wallet.pki.infrastructure.ArtifactWriter;
import se.digg.wallet.pki.infrastructure.EcosystemLayout;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.trustlist.LoteGenerator;
import se.digg.wallet.pki.trustlist.StatusListGenerator;

/** A dedicated leaf signs both trust documents; participant CAs are only LoTE entries. */
public final class TrustSourceFlow {
  private final Organization organization;
  private final EcosystemLayout layout;
  private final ArtifactWriter writer = new ArtifactWriter();

  public TrustSourceFlow(Organization organization, EcosystemLayout layout) {
    this.organization = organization;
    this.layout = layout;
  }

  public SigningIdentity generateSigner(TrustSourceConfig.Signer config,
      CertificateAuthority authority,
      CertificateProfileIssuer certificates, char[] password) {
    var key = new EcKeyGenerator().generateKeyPair();
    var subject =
        new CertificateSubject(config.commonName(), organization, SubjectAlternativeNames.empty());
    var certificate =
        certificates.issueTrustSourceSignerCertificate(subject, key.getPublic(), authority);
    var identity = new SigningIdentity(key, certificate);
    new IdentityStores().write(layout.trustSignerKeystore(), "trust_source", identity, authority,
        password);
    writer.pem(layout.trustSignerCertificate(), certificate);
    return identity;
  }

  public void generateLote(TrustSourceConfig config, WalletTrustAnchors anchors,
      SigningIdentity signer) {
    var generator = new LoteGenerator();
    var document = generator.buildLoteDocument(anchors, config.lote(), organization);
    writer.text(layout.lote(), generator.sign(document, signer));
  }

  public void generateStatusList(TrustSourceConfig.StatusList config, SigningIdentity signer) {
    var token = new StatusListGenerator().buildAndSignStatusList(config.url(),
        StatusListGenerator.DEFAULT_EMPTY_STATUS_LIST, signer.keyPair().getPrivate(),
        signer.certificate(),
        Instant.now(), Duration.ofDays(config.validityDays()));
    writer.text(layout.statusList(), token);
  }
}
