// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import se.digg.wallet.pki.config.PidIssuerConfig;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.crypto.KeystoreManager;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.PidIssuerMaterial;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.trustlist.RegistrationDocuments;

/** PID issuance: three keys in one keystore, followed by the issuer registration JWT. */
public final class PidIssuerFlow {
  private final EcKeyGenerator keys = new EcKeyGenerator();
  private final KeystoreManager keystores = new KeystoreManager();
  private final SecretResolver secrets;

  public PidIssuerFlow(SecretResolver secrets) {
    this.secrets = secrets;
  }

  public void generate(PkiConfiguration config, PrintWriter out) {
    try (var inputs = loadInputs(config)) {
      generate(config, inputs, out);
    }
  }

  static PidIssuerConfig requireConfiguration(PkiConfiguration config) {
    return Checks.required(config.pidIssuer(), "pidIssuer");
  }

  ServicePkiInputs loadInputs(PkiConfiguration config) {
    var pidIssuer = requireConfiguration(config);
    return ServicePkiInputs.load(config, AuthorityRole.PID_ISSUER,
        pidIssuer.keystorePassword(), secrets);
  }

  void generate(PkiConfiguration config, ServicePkiInputs inputs, PrintWriter out) {
    var pidIssuer = config.pidIssuer();
    var authority = inputs.authority();
    var organization = config.organization();
    var outputDirectory = Path.of(config.outputDirectory());
    var certificates =
        new CertificateProfileIssuer(new SecureRandom(), config.publication().baseUrl());
    var signingKey = keys.generateKeyPair();
    var signing = new SigningIdentity(signingKey,
        certificates.issuePidSigningCertificate(pidIssuer.signing().subject(organization),
            signingKey.getPublic(), authority));
    var nonceKey = keys.generateKeyPair();
    var nonce = new SigningIdentity(nonceKey, certificates.issueEncryptionCertificate(
        new CertificateSubject("nonce-encryption", organization,
            pidIssuer.encryption().subjectAlternativeNames()),
        nonceKey.getPublic(), authority));
    var requestKey = keys.generateKeyPair();
    var request = new SigningIdentity(requestKey, certificates.issueEncryptionCertificate(
        new CertificateSubject("request-encryption", organization,
            pidIssuer.encryption().subjectAlternativeNames()),
        requestKey.getPublic(), authority));
    var material = new PidIssuerMaterial(authority, signing, nonce, request);
    writeKeystore(material, outputDirectory.resolve(pidIssuer.keystoreFile()),
        inputs.keystorePassword());
    new RegistrationDocuments().writePidIssuer(pidIssuer.registration(), material.signing(),
        outputDirectory);
    inputs.publishAuthority();
    out.println("Generated: pid-issuer (new keys; selected files replaced)");
  }

  private void writeKeystore(PidIssuerMaterial material, Path keystoreFile, char[] password) {
    var store = keystores.createPkcs12KeyStore();
    addIdentity(store, "pid_issuer", material.signing(), material.authority(), password);
    addIdentity(store, "nonce-encryption", material.nonceEncryption(), material.authority(),
        password);
    addIdentity(store, "request-encryption", material.requestEncryption(), material.authority(),
        password);
    keystores.saveKeyStore(store, keystoreFile, password);
  }

  private void addIdentity(java.security.KeyStore store, String alias, SigningIdentity identity,
      CertificateAuthority authority, char[] password) {
    keystores.addKeyEntry(store, alias, identity.keyPair().getPrivate(), password,
        new Certificate[] {identity.certificate(), authority.certificate()});
  }
}
