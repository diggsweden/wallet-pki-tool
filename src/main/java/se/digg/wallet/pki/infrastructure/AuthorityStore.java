// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Set;
import se.digg.wallet.pki.config.AuthorityConfig;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.PkiConfigurationException;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.WalletRole;

/** Initialization creates absent managed roots; generation only loads existing authority files. */
public final class AuthorityStore {
  private final PkiConfiguration config;
  private final CertificateAuthorityManager manager;
  private final EcKeyGenerator keys = new EcKeyGenerator();

  public AuthorityStore(PkiConfiguration config, Clock clock) {
    this.config = config;
    manager = new CertificateAuthorityManager(keys, new SecureRandom(), clock);
  }

  public void initialize(Set<WalletRole> roles) throws Exception {
    var missing = new ArrayList<WalletRole>();
    for (WalletRole role : roles) {
      if (config.authority(role).source() == AuthorityConfig.Source.EXISTING
          || Files.exists(directory(role), LinkOption.NOFOLLOW_LINKS)) {
        load(role);
      } else {
        missing.add(role);
      }
    }
    for (WalletRole role : missing) {
      Path destination = directory(role);
      ArtifactFiles.rejectSymlinks(destination);
      Path parent =
          Objects.requireNonNull(destination.getParent(), "Authority needs a parent directory");
      ArtifactFiles.directory(parent, true);
      Path temporary = Files.createTempDirectory(parent, ".initializing-");
      try {
        var ca = manager.createAuthority(role.directory(), config.authority(role).commonName(),
            config.organization());
        manager.saveAuthority(ca, temporary);
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
          throw new PkiConfigurationException(
              "Authority appeared during initialization; refusing replacement: " + role.argument());
        }
        Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
      } finally {
        ArtifactFiles.deleteTree(temporary);
      }
    }
  }

  public CertificateAuthority load(WalletRole role) {
    AuthorityConfig source = config.authority(role);
    boolean supplied = source.source() == AuthorityConfig.Source.EXISTING;
    Path certificate =
        supplied ? Path.of(source.certificateFile()) : directory(role).resolve("ca.pem");
    Path key =
        supplied ? Path.of(source.privateKeyFile()) : directory(role).resolve("ca_private_key.pem");
    Path crl =
        supplied ? Path.of(source.crlFile()) : directory(role).resolve("revocation-list.pem");
    if (!Files.isRegularFile(certificate) || !Files.isRegularFile(key)
        || !Files.isRegularFile(crl)) {
      throw new PkiConfigurationException("Missing or incomplete authority for " + role.argument()
          + "; initialize absent managed authorities with init-authorities");
    }
    var root = manager.readCertificatePem(certificate);
    KeyPair pair = new KeyPair(root.getPublicKey(), keys.readPrivateKeyPem(key));
    manager.validateAuthority(pair, root);
    if (!supplied) {
      var expected = new org.bouncycastle.asn1.x500.X500NameBuilder(
          org.bouncycastle.asn1.x500.style.BCStyle.INSTANCE)
          .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.CN, source.commonName())
          .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.O, config.organization().name())
          .addRDN(org.bouncycastle.asn1.x500.style.BCStyle.C, config.organization().country())
          .build();
      if (!expected.equals(org.bouncycastle.asn1.x500.X500Name
          .getInstance(root.getSubjectX500Principal().getEncoded()))) {
        throw new PkiConfigurationException(
            "Managed authority subject differs from configuration: " + role.argument());
      }
    }
    var revocations = manager.readCrlPem(crl);
    manager.validateCrl(revocations, root);
    return new CertificateAuthority(role.directory(), pair, root, revocations);
  }

  public X509Certificate publicCertificate(WalletRole role, String supplied) {
    if (supplied == null && !config.configuredRoles().contains(role)) {
      throw new PkiConfigurationException("LoTE requires certificateFile for " + role.argument());
    }
    Path path = supplied != null ? Path.of(supplied)
        : config.authority(role).source() == AuthorityConfig.Source.EXISTING
            ? Path.of(config.authority(role).certificateFile())
            : directory(role).resolve("ca.pem");
    var certificate = manager.readCertificatePem(path);
    manager.validateRootCertificate(certificate);
    return certificate;
  }

  public void publish(WalletRole role, CertificateAuthority ca, ArtifactLayout layout) {
    var writer = new ArtifactWriter();
    writer.pem(layout.publication(role).resolve("ca.pem"), ca.certificate());
    writer.pem(layout.publication(role).resolve("revocation-list.pem"), ca.crl());
    if (role == WalletRole.TRUST_SOURCE) {
      writer.pem(layout.output().resolve("public/trust-source/revocation-list.pem"), ca.crl());
    }
  }

  public void verifyPublished(WalletRole role, CertificateAuthority ca, ArtifactLayout layout)
      throws Exception {
    if (!ca.certificate()
        .equals(manager.readCertificatePem(layout.publication(role).resolve("ca.pem")))) {
      throw new PkiConfigurationException(
          "Published authority differs from configured root: " + role.argument());
    }
    var crl = manager.readCrlPem(layout.publication(role).resolve("revocation-list.pem"));
    manager.validateCrl(crl, ca.certificate());
    if (!java.util.Arrays.equals(crl.getEncoded(), ca.crl().getEncoded())) {
      throw new PkiConfigurationException(
          "Published CRL differs from supplied CRL: " + role.argument());
    }
  }

  private Path directory(WalletRole role) {
    Path path = Path.of(config.authorityDirectory()).resolve(role.directory());
    ArtifactFiles.rejectSymlinks(path);
    return path;
  }
}
