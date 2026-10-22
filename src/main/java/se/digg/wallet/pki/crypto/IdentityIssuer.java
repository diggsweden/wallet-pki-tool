// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import se.digg.wallet.pki.config.EnvironmentConfiguration.Authority;
import se.digg.wallet.pki.config.EnvironmentConfiguration.Identity;
import se.digg.wallet.pki.storage.ArtifactStore;

/** Issues and persists a complete identity, including profile-specific auxiliary keys. */
public final class IdentityIssuer {
  private final Clock clock;
  private final EcKeyGenerator keys;
  private final CertificateAuthorityManager authorities;
  private final KeystoreManager keystores = new KeystoreManager();

  public IdentityIssuer(Clock clock, EcKeyGenerator keys, CertificateAuthorityManager authorities) {
    this.clock = clock;
    this.keys = keys;
    this.authorities = authorities;
  }

  public record SigningIdentity(PrivateKey key, List<X509Certificate> chain) {
    public SigningIdentity {
      chain = List.copyOf(chain);
    }
  }

  public CertificateAuthority readAuthority(String id, Path directory) {
    var certificate = authorities.readCertificatePem(directory.resolve("ca.pem"));
    var key = keys.readPrivateKeyPem(directory.resolve("ca_private_key.pem"));
    KeyPair pair = new KeyPair(certificate.getPublicKey(), key);
    authorities.validateAuthority(pair, certificate);
    var crl = authorities.readCrlPem(directory.resolve("revocation-list.pem"));
    try {
      crl.verify(certificate.getPublicKey());
      if (crl.getThisUpdate().toInstant().isAfter(clock.instant()) || crl.getNextUpdate() == null
          || !crl.getNextUpdate().toInstant().isAfter(clock.instant())) {
        throw new PkiCryptoException("Authority CRL is outside its validity period: " + id);
      }
    } catch (java.security.GeneralSecurityException e) {
      throw new PkiCryptoException("Cannot validate authority CRL: " + id, e);
    }
    return new CertificateAuthority(id, pair, certificate, crl);
  }

  public CertificateAuthority importAuthority(Authority authority) {
    var certificate = authorities.readCertificatePem(Path.of(authority.certFile()));
    var key = keys.readPrivateKeyPem(Path.of(authority.keyFile()));
    KeyPair pair = new KeyPair(certificate.getPublicKey(), key);
    authorities.validateAuthority(pair, certificate);
    return new CertificateAuthority(authority.id(), pair, certificate,
        authorities.generateEmptyCrl(certificate, pair,
            Duration.between(clock.instant(), certificate.getNotAfter().toInstant())));
  }

  public void saveAuthority(CertificateAuthority authority, Path directory) {
    try {
      ArtifactStore.directory(directory, true);
      authorities.saveAuthority(authority, directory);
    } catch (java.io.IOException e) {
      throw new PkiCryptoException("Cannot persist authority " + authority.id(), e);
    }
  }

  public X509Certificate issue(Identity identity, Authority authority, CertificateAuthority ca,
      Path state, char[] password, boolean rotate, String previousAlias) throws Exception {
    String ref = "identity:" + identity.id();
    Path storePath = ArtifactStore.resource(state, ref, ".p12");
    KeyStore previous = !rotate && Files.exists(storePath)
        ? keystores.loadKeyStore(storePath, password)
        : null;
    KeyStore store = keystores.createPkcs12KeyStore();
    CertificateProfileIssuer issuer = new CertificateProfileIssuer(clock,
        Duration.ofDays(identity.validityDays()), authority.certificateUrl(), authority.crlUrl(),
        identity.cpsUrl());
    KeyPair main = keyPair(previous, previousAlias, password);
    X509Certificate certificate =
        issuer.issueCertificate(identity.certificateConfig(), main.getPublic(), ca);
    keystores.addKeyEntry(store, identity.alias(), main.getPrivate(), password,
        new Certificate[] {certificate, ca.certificate()});
    if (CertificateProfileType.PID_ISSUER_SERVICE.matches(identity.profile())) {
      for (String alias : List.of("nonce-encryption", "request-encryption")) {
        KeyPair pair = keyPair(previous, alias, password);
        var encryptionCertificate = issuer.issueEncryptionCertificate(alias, identity.sans(),
            identity.country(), pair.getPublic(), ca);
        keystores.addKeyEntry(store, alias, pair.getPrivate(), password,
            new Certificate[] {encryptionCertificate, ca.certificate()});
      }
    }
    writeKeyStore(store, storePath, password);
    ArtifactStore.write(ArtifactStore.resource(state, ref, ".crt"),
        keys.toPemString(certificate).getBytes(StandardCharsets.UTF_8), true);
    return certificate;
  }

  public SigningIdentity signingIdentity(Path state, String id, String alias, char[] password)
      throws Exception {
    KeyStore store =
        keystores.loadKeyStore(ArtifactStore.resource(state, "identity:" + id, ".p12"), password);
    List<X509Certificate> chain = new ArrayList<>();
    for (Certificate certificate : store.getCertificateChain(alias)) {
      chain.add((X509Certificate) certificate);
    }
    return new SigningIdentity((PrivateKey) store.getKey(alias, password), chain);
  }

  public void writeTrustStore(Path state, String id,
      java.util.Map<String, X509Certificate> certificates,
      char[] password) throws Exception {
    KeyStore store = keystores.createPkcs12KeyStore();
    for (var entry : certificates.entrySet()) {
      keystores.addCertificateEntry(store, entry.getKey(), entry.getValue());
    }
    writeKeyStore(store, ArtifactStore.resource(state, "truststore:" + id, ".p12"), password);
    verifyTrustStore(state, id, certificates, password);
  }

  public void verifyTrustStore(Path state, String id,
      java.util.Map<String, X509Certificate> certificates, char[] password) throws Exception {
    KeyStore store = keystores.loadKeyStore(
        ArtifactStore.resource(state, "truststore:" + id, ".p12"), password);
    if (store.size() != certificates.size()) {
      throw new PkiCryptoException("Unexpected truststore entries: " + id);
    }
    for (var entry : certificates.entrySet()) {
      if (!store.isCertificateEntry(entry.getKey())
          || !entry.getValue().equals(store.getCertificate(entry.getKey()))) {
        throw new PkiCryptoException("Unexpected truststore certificate: " + id);
      }
    }
  }

  public void verifyIdentity(Identity identity, X509Certificate ca, Path state, char[] password)
      throws Exception {
    KeyStore store = keystores.loadKeyStore(
        ArtifactStore.resource(state, "identity:" + identity.id(), ".p12"), password);
    List<String> expected = new ArrayList<>(List.of(identity.alias()));
    if (CertificateProfileType.PID_ISSUER_SERVICE.matches(identity.profile())) {
      expected.addAll(List.of("nonce-encryption", "request-encryption"));
    }
    if (!new java.util.HashSet<>(Collections.list(store.aliases()))
        .equals(new java.util.HashSet<>(expected))) {
      throw new PkiCryptoException("Unexpected aliases for identity " + identity.id());
    }
    for (String alias : expected) {
      Certificate[] chain = store.getCertificateChain(alias);
      if (chain == null || chain.length != 2 || !chain[1].equals(ca)) {
        throw new PkiCryptoException("Unexpected certificate chain for identity " + identity.id());
      }
      X509Certificate certificate = (X509Certificate) chain[0];
      certificate.checkValidity(Date.from(clock.instant()));
      certificate.verify(ca.getPublicKey());
      if (certificate.getBasicConstraints() >= 0
          || certificate.getNotAfter().after(ca.getNotAfter())) {
        throw new PkiCryptoException("Invalid leaf certificate for identity " + identity.id());
      }
      Signature proof = Signature.getInstance("SHA256withECDSA");
      proof.initSign((PrivateKey) store.getKey(alias, password));
      proof.update(new byte[] {1, 2, 3});
      byte[] signed = proof.sign();
      proof.initVerify(certificate.getPublicKey());
      proof.update(new byte[] {1, 2, 3});
      if (!proof.verify(signed)) {
        throw new PkiCryptoException("Private key does not match identity " + identity.id());
      }
    }
    X509Certificate primary = (X509Certificate) store.getCertificate(identity.alias());
    X509Certificate persisted = authorities.readCertificatePem(
        ArtifactStore.resource(state, "identity:" + identity.id(), ".crt"));
    if (!primary.equals(persisted)) {
      throw new PkiCryptoException("Persisted certificate differs from keystore: " + identity.id());
    }
    verifyRole(identity, primary);
  }

  private static void verifyRole(Identity identity, X509Certificate certificate) {
    if (!CertificateProfileType.PID_ISSUER_SERVICE.matches(identity.profile())
        && !CertificateProfileType.WALLET_PROVIDER_SERVICE.matches(identity.profile())) {
      return;
    }
    byte[] extension = certificate.getExtensionValue(Extension.qCStatements.getId());
    if (extension == null) {
      throw new PkiCryptoException("Missing QC statements for " + identity.id());
    }
    List<String> roles = new ArrayList<>();
    var statements = ASN1Sequence.getInstance(ASN1OctetString.getInstance(extension).getOctets());
    for (var value : statements) {
      var statement = QCStatement.getInstance(value);
      if (statement.getStatementId().equals(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType)) {
        var types = ASN1Sequence.getInstance(statement.getStatementInfo());
        for (var type : types) {
          roles.add(type.toString());
        }
      }
    }
    String expected = CertificateProfileType.PID_ISSUER_SERVICE.matches(identity.profile())
        ? "0.4.0.194126.1.1"
        : "0.4.0.194126.1.2";
    if (!roles.equals(List.of(expected))) {
      throw new PkiCryptoException("Unexpected QC role for " + identity.id());
    }
  }

  private KeyPair keyPair(KeyStore previous, String alias, char[] password) throws Exception {
    if (previous != null && alias != null && previous.containsAlias(alias)) {
      return new KeyPair(previous.getCertificate(alias).getPublicKey(),
          (PrivateKey) previous.getKey(alias, password));
    }
    return keys.generateKeyPair();
  }

  private static void writeKeyStore(KeyStore store, Path destination, char[] password)
      throws Exception {
    try (var bytes = new ByteArrayOutputStream()) {
      store.store(bytes, password);
      ArtifactStore.write(destination, bytes.toByteArray(), true);
    }
  }
}
