// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import se.digg.wallet.pki.config.AuthorityConfig;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.PkiConfigurationException;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.AuthorityRole;

/** Explicit authority lifecycle. Only initialize() can create a managed root. */
public final class AuthorityStore {
  private final PkiConfiguration config;
  private final EcosystemLayout layout;
  private final CertificateAuthorityManager manager = new CertificateAuthorityManager();
  private final EcKeyGenerator keys = new EcKeyGenerator();
  private final ArtifactWriter writer = new ArtifactWriter();

  public AuthorityStore(PkiConfiguration config) {
    this.config = config;
    this.layout = new EcosystemLayout(config);
  }

  private AuthorityConfig settings(AuthorityRole role) {
    return switch (role) {
      case PID_ISSUER -> config.pidIssuer().authority();
      case WALLET_PROVIDER -> config.walletProvider().authority();
      case VERIFIER_ACCESS -> config.verifier().access().authority();
      case VERIFIER_REGISTRATION -> config.verifier().registration().authority();
      case TRUST_SOURCE -> config.trustSource().authority();
    };
  }

  private Path certificatePath(AuthorityRole role) {
    AuthorityConfig authority = settings(role);
    return authority.source() == AuthorityConfig.Source.EXISTING
        ? Path.of(authority.certificateFile())
        : layout.authority(role).resolve("ca.pem");
  }

  private Path keyPath(AuthorityRole role) {
    AuthorityConfig authority = settings(role);
    return authority.source() == AuthorityConfig.Source.EXISTING
        ? Path.of(authority.privateKeyFile())
        : layout.authority(role).resolve("ca_private_key.pem");
  }

  private Path crlPath(AuthorityRole role) {
    AuthorityConfig authority = settings(role);
    return authority.source() == AuthorityConfig.Source.EXISTING
        ? Path.of(authority.crlFile())
        : layout.authority(role).resolve("revocation-list.pem");
  }

  public CertificateAuthority initialize(AuthorityRole role) {
    if (settings(role).source() == AuthorityConfig.Source.MANAGED) {
      boolean anyFileExists = Arrays.asList(keyPath(role), certificatePath(role), crlPath(role))
          .stream().anyMatch(Files::exists);
      if (!anyFileExists) {
        var created = manager.createAuthority(role.directory(), settings(role).commonName(),
            config.organization());
        manager.saveAuthority(created, layout.authority(role));
      }
    }
    var authority = load(role);
    publish(role, authority);
    return authority;
  }

  public CertificateAuthority load(AuthorityRole role) {
    requireFile(keyPath(role), role);
    requireFile(crlPath(role), role);
    X509Certificate certificate = loadPublic(role);
    KeyPair keyPair =
        new KeyPair(certificate.getPublicKey(), keys.readPrivateKeyPem(keyPath(role)));
    manager.validateKeyPair(keyPair, certificate);
    var crl = manager.readCrlPem(crlPath(role));
    manager.validateCrl(crl, certificate);
    return new CertificateAuthority(role.directory(), keyPair, certificate, crl);
  }

  public X509Certificate loadPublic(AuthorityRole role) {
    requireFile(certificatePath(role), role);
    var certificate = manager.readCertificatePem(certificatePath(role));
    manager.validateRootCertificate(certificate);
    if (settings(role).source() == AuthorityConfig.Source.MANAGED) {
      X500Name subject = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
      if (!attribute(subject, BCStyle.CN).equals(settings(role).commonName())
          || !attribute(subject, BCStyle.O).equals(config.organization().name())
          || !attribute(subject, BCStyle.C).equals(config.organization().country())) {
        throw new PkiConfigurationException(
            "Managed authority subject differs from configuration: " + role.directory());
      }
    }
    return certificate;
  }

  private String attribute(X500Name subject, org.bouncycastle.asn1.ASN1ObjectIdentifier type) {
    var values = subject.getRDNs(type);
    return values.length == 1
        ? org.bouncycastle.asn1.x500.style.IETFUtils.valueToString(values[0].getFirst().getValue())
        : "";
  }

  private void requireFile(Path file, AuthorityRole role) {
    if (!Files.isRegularFile(file))
      throw new PkiConfigurationException("Missing authority material for "
          + role.directory() + ": " + file
          + ". Run init-authorities for managed roots; incomplete roots must be repaired, never replaced.");
  }

  public void publish(AuthorityRole role, CertificateAuthority authority) {
    writer.pem(layout.publication(role).resolve("ca.pem"), authority.certificate());
    writer.pem(layout.publication(role).resolve("revocation-list.pem"), authority.crl());
    if (role == AuthorityRole.TRUST_SOURCE)
      writer.pem(layout.output().resolve("trust-source/revocation-list.pem"), authority.crl());
  }
}
