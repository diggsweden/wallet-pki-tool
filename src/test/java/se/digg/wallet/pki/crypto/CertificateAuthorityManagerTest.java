// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.domain.Organization;

class CertificateAuthorityManagerTest {
  private final CertificateAuthorityManager manager = new CertificateAuthorityManager();

  @Test
  void root_certificates_and_crls_have_valid_signatures_and_ca_usage() throws Exception {
    var authority = manager.createAuthority("test-ca", "Example CA",
        new Organization("Example", "NO", "NTRNO-123"));
    var cert = authority.certificate();
    assertThat(cert.getSubjectX500Principal().getName()).contains("CN=Example CA", "O=Example",
        "C=NO");
    assertThat(cert.getIssuerX500Principal()).isEqualTo(cert.getSubjectX500Principal());
    assertThat(cert.getBasicConstraints()).isGreaterThanOrEqualTo(0);
    assertThat(cert.getKeyUsage()[5]).isTrue();
    assertThat(cert.getKeyUsage()[6]).isTrue();
    cert.verify(authority.publicKey());
    authority.crl().verify(authority.publicKey());
  }

  @Test
  void saved_authorities_preserve_certificates_private_keys_and_crls(@TempDir Path directory) {
    var original = manager.createAuthority("test", "Test CA");
    manager.saveAuthority(original, directory);
    assertThat(manager.readCertificatePem(directory.resolve("ca.pem")))
        .isEqualTo(original.certificate());
    assertThat(new EcKeyGenerator().readPrivateKeyPem(directory.resolve("ca_private_key.pem"))
        .getEncoded()).isEqualTo(original.privateKey().getEncoded());
    assertThat(manager.readCrlPem(directory.resolve("revocation-list.pem")))
        .isEqualTo(original.crl());
  }

  @Test
  void mismatched_authority_private_keys_are_rejected() {
    var first = manager.createAuthority("first", "First");
    var second = manager.createAuthority("second", "Second");
    assertThatThrownBy(() -> manager.validateAuthority(
        new java.security.KeyPair(first.publicKey(), second.privateKey()), first.certificate()))
        .hasMessageContaining("Private key does not match");
  }

  @Test
  void malformed_crls_and_certificates_are_rejected() {
    var authority = manager.createAuthority("test", "Test");
    assertThatThrownBy(
        () -> manager.readCrlPem(new EcKeyGenerator().toPemString(authority.certificate())))
        .hasMessageContaining("Unsupported CRL format");
    assertThatThrownBy(() -> manager.readCrlPem("not pem"))
        .hasMessageContaining("No PEM object found");
    assertThatThrownBy(() -> manager.readCertificatePem("not pem"))
        .hasMessageContaining("No PEM object found");
  }
}
