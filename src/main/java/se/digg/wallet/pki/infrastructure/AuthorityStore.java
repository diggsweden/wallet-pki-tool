// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import se.digg.wallet.pki.config.AuthorityConfig;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.PkiConfigurationException;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.WalletRole;
import se.digg.wallet.pki.storage.ArtifactStore;

/** Preserves existing CRLs and pins each role's trust anchor independently of leaf renewal. */
public final class AuthorityStore {
  private final PkiConfiguration config;
  private final CertificateAuthorityManager manager;
  private final EcKeyGenerator keys = new EcKeyGenerator();

  public AuthorityStore(PkiConfiguration config, Clock clock) {
    this.config = config;
    manager = new CertificateAuthorityManager(keys, new SecureRandom(), clock);
  }

  public CertificateAuthority load(WalletRole role, ArtifactLayout layout) {
    AuthorityConfig source = config.authority(role);
    Path certificate = source.source() == AuthorityConfig.Source.EXISTING
        ? Path.of(source.certificateFile())
        : layout.authority(role).resolve("ca.pem");
    Path key = source.source() == AuthorityConfig.Source.EXISTING
        ? Path.of(source.privateKeyFile())
        : layout.authority(role).resolve("ca_private_key.pem");
    Path crl = source.source() == AuthorityConfig.Source.EXISTING
        ? Path.of(source.crlFile())
        : layout.authority(role).resolve("revocation-list.pem");
    var root = manager.readCertificatePem(certificate);
    KeyPair pair = new KeyPair(root.getPublicKey(), keys.readPrivateKeyPem(key));
    manager.validateAuthority(pair, root);
    if (source.source() == AuthorityConfig.Source.MANAGED) {
      var expected = new org.bouncycastle.asn1.x500.X500NameBuilder(
          org.bouncycastle.asn1.x500.style.BCStyle.INSTANCE)
          .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, source.commonName())
          .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.O, config.organization().name())
          .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.C, config.organization().country())
          .build();
      if (!expected.equals(org.bouncycastle.asn1.x500.X500Name
          .getInstance(root.getSubjectX500Principal().getEncoded()))) {
        throw new PkiConfigurationException(
            "Managed authority subject changed; coordinate rollover for " + role.argument());
      }
    }
    var revocations = manager.readCrlPem(crl);
    manager.validateCrl(revocations, root);
    return new CertificateAuthority(role.directory(), pair, root, revocations);
  }

  public CertificateAuthority create(WalletRole role, ArtifactLayout layout) {
    if (config.authority(role).source() != AuthorityConfig.Source.MANAGED) {
      throw new PkiConfigurationException("Only explicitly managed authorities can be created");
    }
    var root = manager.createAuthority(role.directory(), config.authority(role).commonName(),
        config.organization());
    try {
      ArtifactStore.directory(layout.authority(role), true);
    } catch (java.io.IOException e) {
      throw new PkiConfigurationException("Cannot create authority directory", e);
    }
    manager.saveAuthority(root, layout.authority(role));
    return root;
  }

  public X509Certificate publicCertificate(WalletRole role, ArtifactLayout layout,
      String supplied) {
    if (supplied == null && !config.configuredRoles().contains(role)) {
      throw new PkiConfigurationException("LoTE requires certificateFile for " + role.argument());
    }
    Path path = supplied != null ? Path.of(supplied)
        : config.authority(role).source() == AuthorityConfig.Source.EXISTING
            ? Path.of(config.authority(role).certificateFile())
            : layout.authority(role).resolve("ca.pem");
    var certificate = manager.readCertificatePem(path);
    manager.validateRootCertificate(certificate);
    return certificate;
  }

  public void publish(WalletRole role, CertificateAuthority ca, ArtifactLayout layout) {
    var writer = new ArtifactWriter();
    writer.pem(layout.authority(role).resolve("ca.pem"), ca.certificate());
    writer.pem(layout.authority(role).resolve("revocation-list.pem"), ca.crl());
    writer.pem(layout.publication(role).resolve("ca.pem"), ca.certificate());
    writer.pem(layout.publication(role).resolve("revocation-list.pem"), ca.crl());
    if (role == WalletRole.TRUST_SOURCE) {
      writer.pem(layout.output().resolve("public/trust-source/revocation-list.pem"), ca.crl());
    }
  }

  public void verifyPublished(WalletRole role, CertificateAuthority ca, ArtifactLayout layout)
      throws Exception {
    for (Path path : java.util.List.of(layout.authority(role).resolve("ca.pem"),
        layout.publication(role).resolve("ca.pem"))) {
      if (!ca.certificate().equals(manager.readCertificatePem(path))) {
        throw new PkiConfigurationException(
            "Published authority differs from configured root: " + role.argument());
      }
    }
    var crl = manager.readCrlPem(layout.publication(role).resolve("revocation-list.pem"));
    manager.validateCrl(crl, ca.certificate());
    if (!java.util.Arrays.equals(crl.getEncoded(), ca.crl().getEncoded())) {
      throw new PkiConfigurationException(
          "Published CRL differs from supplied CRL: " + role.argument());
    }
  }
}
