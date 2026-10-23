// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.io.ByteArrayOutputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Collections;
import java.util.Date;
import java.util.Set;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.KeystoreManager;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import se.digg.wallet.pki.domain.PidIssuerMaterial;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.WalletRole;

/** Shared PKCS12 mechanics; wallet flows own the profile recipes and aliases. */
public final class IdentityStores {
  private final KeystoreManager stores = new KeystoreManager();
  private final Clock clock;

  public IdentityStores(Clock clock) {
    this.clock = clock;
  }

  public void write(WalletRole role, SigningIdentity identity, CertificateAuthority ca,
      ArtifactLayout layout, char[] password) throws Exception {
    KeyStore store = stores.createSingleKeyStore(role.alias(), identity.keyPair().getPrivate(),
        identity.certificate(), ca.certificate(), password);
    save(store, layout.keystore(role), password);
  }

  public void writePid(PidIssuerMaterial material, ArtifactLayout layout, char[] password)
      throws Exception {
    KeyStore store = stores.createPkcs12KeyStore();
    add(store, "pid_issuer", material.signing(), material.authority(), password);
    add(store, "nonce-encryption", material.nonceEncryption(), material.authority(), password);
    add(store, "request-encryption", material.requestEncryption(), material.authority(), password);
    save(store, layout.pidKeystore(), password);
  }

  public X509Certificate verify(WalletRole role, CertificateAuthority ca, ArtifactLayout layout,
      char[] password) throws Exception {
    KeyStore store = stores.loadKeyStore(layout.keystore(role), password);
    Set<String> expected = role == WalletRole.PID_ISSUER
        ? Set.of("pid_issuer", "nonce-encryption", "request-encryption")
        : Set.of(role.alias());
    if (!Set.copyOf(Collections.list(store.aliases())).equals(expected)) {
      throw new PkiCryptoException("Unexpected aliases for " + role.argument());
    }
    for (String alias : expected) {
      var chain = store.getCertificateChain(alias);
      if (chain == null || chain.length != 2 || !chain[1].equals(ca.certificate())) {
        throw new PkiCryptoException("Unexpected certificate chain for " + alias);
      }
      var certificate = (X509Certificate) chain[0];
      certificate.checkValidity(Date.from(clock.instant()));
      certificate.verify(ca.publicKey());
      if (certificate.getBasicConstraints() >= 0
          || certificate.getNotAfter().after(ca.certificate().getNotAfter())) {
        throw new PkiCryptoException("Invalid certificate lifetime for " + alias);
      }
      Signature proof = Signature.getInstance("SHA256withECDSA");
      proof.initSign((PrivateKey) store.getKey(alias, password));
      proof.update(new byte[] {1, 2, 3});
      byte[] signed = proof.sign();
      proof.initVerify(certificate.getPublicKey());
      proof.update(new byte[] {1, 2, 3});
      if (!proof.verify(signed)) {
        throw new PkiCryptoException("Private key mismatch for " + alias);
      }
    }
    return (X509Certificate) store.getCertificate(role.alias());
  }

  private void add(KeyStore store, String alias, SigningIdentity identity, CertificateAuthority ca,
      char[] password) {
    stores.addKeyEntry(store, alias, identity.keyPair().getPrivate(), password,
        new Certificate[] {identity.certificate(), ca.certificate()});
  }

  private static void save(KeyStore store, Path path, char[] password) throws Exception {
    try (var bytes = new ByteArrayOutputStream()) {
      store.store(bytes, password);
      ArtifactFiles.write(path, bytes.toByteArray(), true);
    }
  }
}
