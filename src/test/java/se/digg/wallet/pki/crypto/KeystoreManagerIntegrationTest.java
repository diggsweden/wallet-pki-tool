// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;

class KeystoreManagerIntegrationTest {
  @TempDir
  Path directory;
  private final KeystoreManager stores = new KeystoreManager();

  @Test
  void single_key_stores_preserve_private_keys_and_certificate_chains() throws Exception {
    var authority = new CertificateAuthorityManager().createAuthority("test", "Test CA");
    final var identity = identity(authority, "Service");
    final char[] password = "test-password".toCharArray();
    Path file = directory.resolve("nested/service.p12");
    var store = stores.createSingleKeyStore("service", identity.keyPair().getPrivate(),
        identity.certificate(), authority.certificate(), password);

    stores.saveKeyStore(store, file, password);

    var loaded = stores.loadKeyStore(file, password);
    assertThat(loaded.getKey("service", password).getEncoded())
        .isEqualTo(identity.keyPair().getPrivate().getEncoded());
    assertThat(loaded.getCertificateChain("service"))
        .containsExactly(identity.certificate(), authority.certificate());
  }

  @Test
  void multi_key_stores_preserve_every_alias_key_and_chain() throws Exception {
    var authority = new CertificateAuthorityManager().createAuthority("test", "Test CA");
    final var identities = Map.of(
        "pid_issuer", identity(authority, "Issuer"),
        "nonce-encryption", identity(authority, "Nonce"),
        "request-encryption", identity(authority, "Request"));
    final char[] password = "test-password".toCharArray();
    Path file = directory.resolve("issuer.p12");
    var store = stores.createPkcs12KeyStore();
    for (var entry : identities.entrySet()) {
      var identity = entry.getValue();
      stores.addKeyEntry(store, entry.getKey(), identity.keyPair().getPrivate(), password,
          new Certificate[] {identity.certificate(), authority.certificate()});
    }

    stores.saveKeyStore(store, file, password);

    var loaded = stores.loadKeyStore(file, password);
    assertThat(Collections.list(loaded.aliases()))
        .containsExactlyInAnyOrderElementsOf(identities.keySet());
    for (var entry : identities.entrySet()) {
      assertThat(loaded.getKey(entry.getKey(), password).getEncoded())
          .as(entry.getKey()).isEqualTo(entry.getValue().keyPair().getPrivate().getEncoded());
      assertThat(loaded.getCertificateChain(entry.getKey()))
          .as(entry.getKey())
          .containsExactly(entry.getValue().certificate(), authority.certificate());
    }
  }

  @Test
  void truststores_preserve_certificate_entries() throws Exception {
    var authority = new CertificateAuthorityManager().createAuthority("test", "Test CA");
    final var identity = identity(authority, "Service");
    final char[] password = "test-password".toCharArray();
    Path file = directory.resolve("trust.p12");
    var store = stores.createPkcs12KeyStore();
    stores.addCertificateEntry(store, "issuer", identity.certificate());
    stores.addCertificateEntry(store, "authority", authority.certificate());

    stores.saveKeyStore(store, file, password);

    var loaded = stores.loadKeyStore(file, password);
    assertThat(loaded.size()).isEqualTo(2);
    assertThat(loaded.isCertificateEntry("issuer")).isTrue();
    assertThat(loaded.isCertificateEntry("authority")).isTrue();
    assertThat(loaded.getCertificate("issuer")).isEqualTo(identity.certificate());
    assertThat(loaded.getCertificate("authority")).isEqualTo(authority.certificate());
  }

  @Test
  void incorrect_keystore_passwords_are_rejected() {
    Path file = directory.resolve("protected.p12");
    stores.saveKeyStore(stores.createPkcs12KeyStore(), file, "correct-password".toCharArray());

    assertThatThrownBy(() -> stores.loadKeyStore(file, "wrong-password".toCharArray()))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Failed to load PKCS#12 KeyStore");
  }

  @Test
  void missing_keystore_files_are_rejected() {
    assertThatThrownBy(() -> stores.loadKeyStore(directory.resolve("missing.p12"), new char[0]))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("KeyStore file not found");
  }

  private SigningIdentity identity(CertificateAuthority authority, String commonName) {
    var key = new EcKeyGenerator().generateKeyPair();
    var subject = new CertificateSubject(commonName,
        new Organization("Test", "SE", "VATSE-12345678"), SubjectAlternativeNames.empty());
    var certificate = new CertificateProfileIssuer()
        .issuePidSigningCertificate(subject, key.getPublic(), authority);
    return new SigningIdentity(key, certificate);
  }
}
