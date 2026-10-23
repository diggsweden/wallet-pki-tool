// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.nio.file.Path;
import se.digg.wallet.pki.config.VerifierConfig;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.trustlist.RegistrationDocuments;

/** The verifier's access certificate and registration signer have separate flows and CAs. */
public final class VerifierFlow {
  private final Organization organization;
  private final CertificateProfileIssuer certificates;
  private final Path outputDirectory;
  private final EcKeyGenerator keys = new EcKeyGenerator();
  private final IdentityStores stores = new IdentityStores();

  public VerifierFlow(Organization organization, CertificateProfileIssuer certificates,
      Path outputDirectory) {
    this.organization = organization;
    this.certificates = certificates;
    this.outputDirectory = outputDirectory;
  }

  public void generateAccess(VerifierConfig.Access config, CertificateAuthority authority,
      char[] password) {
    var key = keys.generateKeyPair();
    var subject =
        new CertificateSubject(config.commonName(), organization, config.subjectAlternativeNames());
    var certificate =
        certificates.issueRelyingPartyAccessCertificate(subject, key.getPublic(), authority);
    stores.write(outputDirectory.resolve(config.keystoreFile()), "verifier_access_certificate",
        new SigningIdentity(key, certificate), authority, password);
  }

  public void generateRegistration(VerifierConfig.Registration config,
      CertificateAuthority authority, char[] password) {
    var key = keys.generateKeyPair();
    var subject =
        new CertificateSubject(config.commonName(), organization, SubjectAlternativeNames.empty());
    var certificate =
        certificates.issueRelyingPartyRegistrationCertificate(subject, key.getPublic(), authority);
    var identity = new SigningIdentity(key, certificate);
    stores.write(outputDirectory.resolve(config.keystoreFile()), "registration", identity,
        authority,
        password);
    new RegistrationDocuments().writeVerifier(config.registration(), organization, identity,
        authority, outputDirectory);
  }
}
