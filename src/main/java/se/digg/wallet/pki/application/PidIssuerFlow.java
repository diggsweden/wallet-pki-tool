// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.security.SecureRandom;
import java.time.Clock;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.PidIssuerMaterial;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.infrastructure.ArtifactLayout;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.trustlist.RegistrationDocuments;

/**
 * The PID issuer always receives signing, nonce-encryption and request-encryption keys together.
 */
final class PidIssuerFlow {
  static void generate(PkiConfiguration config, CertificateAuthority ca, ArtifactLayout layout,
      Clock clock, char[] password) throws Exception {
    var keys = new EcKeyGenerator();
    var pid = config.pidIssuer();
    var issuer =
        new CertificateProfileIssuer(new SecureRandom(), config.publicationBaseUrl(), clock);
    var signingKey = keys.generateKeyPair();
    var signing = new SigningIdentity(signingKey, issuer.issuePidSigningCertificate(
        pid.signing().subject(config.organization()), signingKey.getPublic(), ca));
    var nonceKey = keys.generateKeyPair();
    var nonce = new SigningIdentity(nonceKey, issuer.issueEncryptionCertificate(
        new CertificateSubject("nonce-encryption", config.organization(),
            pid.encryption().subjectAlternativeNames()),
        nonceKey.getPublic(), ca));
    var requestKey = keys.generateKeyPair();
    var request = new SigningIdentity(requestKey, issuer.issueEncryptionCertificate(
        new CertificateSubject("request-encryption", config.organization(),
            pid.encryption().subjectAlternativeNames()),
        requestKey.getPublic(), ca));
    new IdentityStores(clock).writePid(new PidIssuerMaterial(ca, signing, nonce, request), layout,
        password);
    new RegistrationDocuments(clock).writePidIssuer(pid.registration(), signing, layout);
  }
}
