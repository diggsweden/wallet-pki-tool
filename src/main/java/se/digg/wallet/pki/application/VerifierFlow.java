// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.time.Clock;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;
import se.digg.wallet.pki.domain.WalletRole;
import se.digg.wallet.pki.infrastructure.ArtifactLayout;
import se.digg.wallet.pki.infrastructure.ArtifactWriter;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.trustlist.RegistrationDocuments;

/** Separate verifier access and registration flows retain their own CAs and aliases. */
final class VerifierFlow {
  static void access(PkiConfiguration config, CertificateAuthority ca, ArtifactLayout layout,
      Clock clock, char[] password) throws Exception {
    var stores = new IdentityStores(clock);
    var access = config.verifier().access();
    var key = new se.digg.wallet.pki.crypto.EcKeyGenerator().generateKeyPair();
    var issuer = new CertificateProfileIssuer(new java.security.SecureRandom(),
        config.publicationBaseUrl(), clock);
    var subject = new CertificateSubject(access.commonName(), config.organization(),
        access.subjectAlternativeNames());
    var identity = new SigningIdentity(key,
        issuer.issueRelyingPartyAccessCertificate(subject, key.getPublic(), ca));
    stores.write(WalletRole.VERIFIER_ACCESS, identity, ca, layout, password);
    new ArtifactWriter().text(layout.publication(WalletRole.VERIFIER_ACCESS).resolve("cps.md"),
        "# DIGG Wallet Environment CPS\n\n"
            + "Test certificate policy for wallet relying party access.\n");
  }

  static void registration(PkiConfiguration config, CertificateAuthority ca, ArtifactLayout layout,
      Clock clock, char[] password) throws Exception {
    var stores = new IdentityStores(clock);
    var registration = config.verifier().registration();
    var key =
        new se.digg.wallet.pki.crypto.EcKeyGenerator().generateKeyPair();
    var issuer = new CertificateProfileIssuer(new java.security.SecureRandom(),
        config.publicationBaseUrl(), clock);
    var subject = new CertificateSubject(registration.commonName(), config.organization(),
        SubjectAlternativeNames.empty());
    var identity = new SigningIdentity(key,
        issuer.issueRelyingPartyRegistrationCertificate(subject, key.getPublic(), ca));
    stores.write(WalletRole.VERIFIER_REGISTRATION, identity, ca, layout, password);

    new RegistrationDocuments(clock).writeVerifier(registration.registration(),
        config.organization(),
        identity, ca, layout);
  }
}
