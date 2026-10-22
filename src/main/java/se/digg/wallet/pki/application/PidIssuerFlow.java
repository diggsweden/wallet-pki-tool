// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.security.cert.Certificate;
import se.digg.wallet.pki.config.PidIssuerConfig;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.crypto.KeystoreManager;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.PidIssuerMaterial;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.infrastructure.EcosystemLayout;
import se.digg.wallet.pki.trustlist.RegistrationDocuments;

/** PID issuance: three keys in one keystore, followed by the issuer registration JWT. */
public final class PidIssuerFlow {
  private final EcKeyGenerator keys = new EcKeyGenerator();
  private final KeystoreManager keystores = new KeystoreManager();
  private final CertificateProfileIssuer certificates;
  private final Organization organization;
  private final EcosystemLayout layout;

  public PidIssuerFlow(Organization organization, CertificateProfileIssuer certificates,
      EcosystemLayout layout) {
    this.organization = organization;
    this.certificates = certificates;
    this.layout = layout;
  }

  public void generate(PidIssuerConfig config, CertificateAuthority authority, char[] password) {
    var signingKey = keys.generateKeyPair();
    var signing = new SigningIdentity(signingKey,
        certificates.issuePidSigningCertificate(config.signing().subject(organization),
            signingKey.getPublic(), authority));
    var nonceKey = keys.generateKeyPair();
    var nonce = new SigningIdentity(nonceKey, certificates.issueEncryptionCertificate(
        new CertificateSubject("nonce-encryption", organization,
            config.encryption().subjectAlternativeNames()),
        nonceKey.getPublic(), authority));
    var requestKey = keys.generateKeyPair();
    var request = new SigningIdentity(requestKey, certificates.issueEncryptionCertificate(
        new CertificateSubject("request-encryption", organization,
            config.encryption().subjectAlternativeNames()),
        requestKey.getPublic(), authority));
    var material = new PidIssuerMaterial(authority, signing, nonce, request);
    writeKeystore(material, password);
    new RegistrationDocuments().writePidIssuer(config.registration(), material.signing(), layout);
  }

  private void writeKeystore(PidIssuerMaterial material, char[] password) {
    var store = keystores.createPkcs12KeyStore();
    addIdentity(store, "pid_issuer", material.signing(), material.authority(), password);
    addIdentity(store, "nonce-encryption", material.nonceEncryption(), material.authority(),
        password);
    addIdentity(store, "request-encryption", material.requestEncryption(), material.authority(),
        password);
    keystores.saveKeyStore(store, layout.pidKeystore(), password);
  }

  private void addIdentity(java.security.KeyStore store, String alias, SigningIdentity identity,
      CertificateAuthority authority, char[] password) {
    keystores.addKeyEntry(store, alias, identity.keyPair().getPrivate(), password,
        new Certificate[] {identity.certificate(), authority.certificate()});
  }
}
