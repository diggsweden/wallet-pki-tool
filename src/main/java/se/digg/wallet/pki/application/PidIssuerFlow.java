// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.time.Clock;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.PidIssuerMaterial;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.WalletRole;
import se.digg.wallet.pki.infrastructure.EcosystemLayout;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.trustlist.RegistrationDocuments;

/** PID signing, nonce and request encryption are one identity lifecycle. */
final class PidIssuerFlow {
  static void provision(PkiConfiguration config, CertificateAuthority ca, EcosystemLayout layout,
      Clock clock, char[] password, boolean issue, boolean rotate) throws Exception {
    var stores = new IdentityStores(clock);
    var pid = config.pidIssuer();
    if (issue) {
      var issuer = new CertificateProfileIssuer(new java.security.SecureRandom(),
          config.publicationBaseUrl(), clock);
      var signingKey = stores.keyPair(layout.pidKeystore(), "pid_issuer", password, rotate);
      var signing = new SigningIdentity(signingKey, issuer.issuePidSigningCertificate(
          pid.signing().subject(config.organization()), signingKey.getPublic(), ca));
      var nonceKey = stores.keyPair(layout.pidKeystore(), "nonce-encryption", password, rotate);
      var nonce = new SigningIdentity(nonceKey, issuer.issueEncryptionCertificate(
          new CertificateSubject("nonce-encryption", config.organization(),
              pid.encryption().subjectAlternativeNames()),
          nonceKey.getPublic(), ca));
      var requestKey = stores.keyPair(layout.pidKeystore(), "request-encryption", password, rotate);
      var request = new SigningIdentity(requestKey, issuer.issueEncryptionCertificate(
          new CertificateSubject("request-encryption", config.organization(),
              pid.encryption().subjectAlternativeNames()),
          requestKey.getPublic(), ca));
      stores.writePid(new PidIssuerMaterial(ca, signing, nonce, request), layout, password);
    }
    var identity = stores.read(layout.pidKeystore(), WalletRole.PID_ISSUER.alias(), password);
    new RegistrationDocuments(clock).writePidIssuer(pid.registration(), identity, layout);
  }
}
