// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.io.PrintWriter;
import java.nio.file.Path;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.config.VerifierConfig;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.trustlist.RegistrationDocuments;

/** The verifier's access certificate and registration signer have separate flows and CAs. */
public final class VerifierFlow {
  private final SecretResolver secrets;
  private final EcKeyGenerator keys = new EcKeyGenerator();
  private final IdentityStores stores = new IdentityStores();

  public VerifierFlow(SecretResolver secrets) {
    this.secrets = secrets;
  }

  static VerifierConfig.Access requireAccessConfiguration(PkiConfiguration config) {
    var verifier = Checks.required(config.verifier(), "verifier");
    return Checks.required(verifier.access(), "verifier.access");
  }

  static VerifierConfig.Registration requireRegistrationConfiguration(PkiConfiguration config) {
    var verifier = Checks.required(config.verifier(), "verifier");
    return Checks.required(verifier.registration(), "verifier.registration");
  }

  ServicePkiInputs loadAccessInputs(PkiConfiguration config) {
    var access = requireAccessConfiguration(config);
    return ServicePkiInputs.load(config, AuthorityRole.VERIFIER_ACCESS,
        access.keystorePassword(), secrets);
  }

  ServicePkiInputs loadRegistrationInputs(PkiConfiguration config) {
    var registration = requireRegistrationConfiguration(config);
    return ServicePkiInputs.load(config, AuthorityRole.VERIFIER_REGISTRATION,
        registration.keystorePassword(), secrets);
  }

  public void generateAccess(PkiConfiguration config, PrintWriter out) {
    try (var inputs = loadAccessInputs(config)) {
      generateAccess(config, inputs, out);
    }
  }

  void generateAccess(PkiConfiguration config, ServicePkiInputs inputs, PrintWriter out) {
    var access = config.verifier().access();
    var authority = inputs.authority();
    var certificates = new CertificateProfileIssuer(config.caDistribution().baseUrl());
    var key = keys.generateKeyPair();
    var subject = new CertificateSubject(access.commonName(), config.organization(),
        access.subjectAlternativeNames());
    var certificate =
        certificates.issueRelyingPartyAccessCertificate(subject, key.getPublic(), authority);
    stores.write(Path.of(config.outputDirectory()).resolve(access.keystoreFile()),
        "verifier_access_certificate", new SigningIdentity(key, certificate),
        authority, inputs.keystorePassword());
    inputs.publishAuthority();
    out.println("Generated: verifier-access (new keys; selected files replaced)");
  }

  public void generateRegistration(PkiConfiguration config, PrintWriter out) {
    try (var inputs = loadRegistrationInputs(config)) {
      generateRegistration(config, inputs, out);
    }
  }

  void generateRegistration(PkiConfiguration config, ServicePkiInputs inputs, PrintWriter out) {
    var registration = config.verifier().registration();
    var authority = inputs.authority();
    var outputDirectory = Path.of(config.outputDirectory());
    var certificates = new CertificateProfileIssuer(config.caDistribution().baseUrl());
    var key = keys.generateKeyPair();
    var subject = new CertificateSubject(registration.commonName(), config.organization(),
        SubjectAlternativeNames.empty());
    var certificate =
        certificates.issueRelyingPartyRegistrationCertificate(subject, key.getPublic(), authority);
    var identity = new SigningIdentity(key, certificate);
    stores.write(outputDirectory.resolve(registration.keystoreFile()), "registration", identity,
        authority, inputs.keystorePassword());
    new RegistrationDocuments().writeVerifier(registration.registration(), config.organization(),
        identity, authority, outputDirectory);
    inputs.publishAuthority();
    out.println("Generated: verifier-registration (new keys; selected files replaced)");
  }
}
