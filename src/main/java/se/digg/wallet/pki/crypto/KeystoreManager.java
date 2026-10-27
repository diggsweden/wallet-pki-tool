// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;

/** Manages creation, modification, and persistence of PKCS#12 (.p12) keystores and truststores. */
public class KeystoreManager {

  private static final String KEYSTORE_TYPE_PKCS12 = "PKCS12";

  /** Creates a new empty PKCS#12 KeyStore in memory. */
  public KeyStore createPkcs12KeyStore() {
    try {
      KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE_PKCS12);
      keyStore.load(null, null);
      return keyStore;
    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
      throw new PkiCryptoException("Failed to initialize PKCS#12 KeyStore", e);
    }
  }

  /** Adds a private key and certificate chain to the keystore. */
  public void addKeyEntry(
      KeyStore keyStore,
      String alias,
      PrivateKey privateKey,
      char[] password,
      Certificate[] certificateChain) {
    Objects.requireNonNull(keyStore, "keyStore must not be null");
    Objects.requireNonNull(alias, "alias must not be null");
    Objects.requireNonNull(privateKey, "privateKey must not be null");
    Objects.requireNonNull(certificateChain, "certificateChain must not be null");

    try {
      char[] passCopy = password != null ? password.clone() : new char[0];
      Certificate[] chainCopy = certificateChain.clone();
      keyStore.setKeyEntry(alias, privateKey, passCopy, chainCopy);
    } catch (KeyStoreException e) {
      throw new PkiCryptoException("Failed to add key entry with alias: " + alias, e);
    }
  }

  /** Adds a trusted certificate entry to the keystore (for truststore creation). */
  public void addCertificateEntry(KeyStore keyStore, String alias, Certificate certificate) {
    Objects.requireNonNull(keyStore, "keyStore must not be null");
    Objects.requireNonNull(alias, "alias must not be null");
    Objects.requireNonNull(certificate, "certificate must not be null");

    try {
      keyStore.setCertificateEntry(alias, certificate);
    } catch (KeyStoreException e) {
      throw new PkiCryptoException("Failed to add certificate entry with alias: " + alias, e);
    }
  }

  /** Creates a PKCS#12 keystore containing a single service certificate and CA chain. */
  public KeyStore createSingleKeyStore(
      String alias,
      PrivateKey serviceKey,
      X509Certificate serviceCert,
      X509Certificate caCert,
      char[] password) {
    KeyStore keyStore = createPkcs12KeyStore();
    Certificate[] chain = (caCert != null)
        ? new Certificate[] {serviceCert, caCert}
        : new Certificate[] {serviceCert};
    addKeyEntry(keyStore, alias, serviceKey, password, chain);
    return keyStore;
  }

  /**
   * Saves the KeyStore atomically with mode 0644 on POSIX filesystems, creating parent directories
   * if needed.
   */
  public void saveKeyStore(KeyStore keyStore, Path outputPath, char[] password) {
    Objects.requireNonNull(keyStore, "keyStore must not be null");
    Objects.requireNonNull(outputPath, "outputPath must not be null");

    Path temporary = null;
    try {
      Path absolute = outputPath.toAbsolutePath();
      Path parent = absolute.getParent();
      if (parent == null) {
        throw new PkiCryptoException("Keystore path must name a file: " + outputPath);
      }
      Files.createDirectories(parent);
      temporary = Files.createTempFile(parent, ".wallet-pki-", ".tmp");
      if (Files.getFileAttributeView(temporary, PosixFileAttributeView.class) != null) {
        Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rw-r--r--"));
      }

      char[] passCopy = password != null ? password.clone() : new char[0];
      try (OutputStream os = Files.newOutputStream(temporary)) {
        keyStore.store(os, passCopy);
      }
      Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING);
    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
      throw new PkiCryptoException("Failed to save PKCS#12 KeyStore to: " + outputPath, e);
    } finally {
      if (temporary != null) {
        try {
          Files.deleteIfExists(temporary);
        } catch (IOException e) {
          throw new PkiCryptoException("Cannot remove temporary keystore: " + temporary, e);
        }
      }
    }
  }

  /** Loads an existing PKCS#12 KeyStore from disk. */
  public KeyStore loadKeyStore(Path keystorePath, char[] password) {
    Objects.requireNonNull(keystorePath, "keystorePath must not be null");

    if (!Files.exists(keystorePath)) {
      throw new PkiCryptoException("KeyStore file not found: " + keystorePath);
    }

    try {
      KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE_PKCS12);
      char[] passCopy = password != null ? password.clone() : new char[0];
      try (InputStream is = Files.newInputStream(keystorePath)) {
        keyStore.load(is, passCopy);
      }
      return keyStore;
    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
      throw new PkiCryptoException("Failed to load PKCS#12 KeyStore from: " + keystorePath, e);
    }
  }
}
