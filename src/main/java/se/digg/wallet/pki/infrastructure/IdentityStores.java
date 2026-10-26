// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.KeystoreManager;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import se.digg.wallet.pki.domain.SigningIdentity;

/** PKCS#12 mechanics shared by the named role flows. */
public final class IdentityStores {
  private final KeystoreManager keystores = new KeystoreManager();

  public void write(Path file, String alias, SigningIdentity identity,
      CertificateAuthority authority, char[] password) {
    var store = keystores.createSingleKeyStore(alias, identity.keyPair().getPrivate(),
        identity.certificate(), authority.certificate(), password);
    keystores.saveKeyStore(store, file, password);
  }

  public SigningIdentity loadTrustSigner(Path file, char[] password, X509Certificate authority) {
    var store = keystores.loadKeyStore(file, password);
    try {
      var certificate = (X509Certificate) store.getCertificate("trust_source");
      var key = (PrivateKey) store.getKey("trust_source", password);
      var chain = store.getCertificateChain("trust_source");
      if (certificate == null || key == null || chain == null || chain.length != 2
          || !chain[1].equals(authority)) {
        throw new PkiCryptoException(
            "Expected trust_source leaf and configured authority in " + file);
      }
      certificate.checkValidity();
      certificate.verify(authority.getPublicKey());
      new CertificateAuthorityManager()
          .validateKeyPair(new KeyPair(certificate.getPublicKey(), key), certificate);
      boolean[] usage = certificate.getKeyUsage();
      if (usage == null || !usage[0])
        throw new PkiCryptoException("Trust signer lacks digitalSignature usage");
      return new SigningIdentity(new KeyPair(certificate.getPublicKey(), key), certificate);
    } catch (java.security.GeneralSecurityException e) {
      throw new PkiCryptoException("Cannot load trust-source signing identity: " + file, e);
    }
  }
}
