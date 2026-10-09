// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.util.Base64;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.List;
import java.util.Objects;
import se.digg.wallet.pki.crypto.PkiCryptoException;

/**
 * Signs and verifies Trust Lists (LoTE) and Status Lists as compact JWS/JWT tokens using ECDSA
 * P-256 (ES256) with embedded X.509 certificate chains (x5c) and ETSI/OAuth typ headers.
 */
public class TrustListSigner {

  public static final String TYPE_TRUSTLIST_JWT = "trustlist+jwt";
  public static final String TYPE_STATUSLIST_JWT = "statuslist+jwt";

  /**
   * Signs a JSON payload as a compact JWS with ES256, embedded X.509 certificate chain, and default
   * 'trustlist+jwt' typ header according to ETSI TS 119 602.
   *
   * @param jsonPayload the JSON payload string to sign
   * @param privateKey the private key for ES256 signing
   * @param signingCert the X.509 certificate to embed in the x5c header
   * @return compact JWS string (header.payload.signature)
   */
  public String signJws(String jsonPayload, PrivateKey privateKey, X509Certificate signingCert) {
    return signJws(jsonPayload, privateKey, signingCert, TYPE_TRUSTLIST_JWT);
  }

  /**
   * Signs a JSON payload as a compact JWS with ES256, embedded X.509 certificate chain, and custom
   * typ header.
   *
   * @param jsonPayload the JSON payload string to sign
   * @param privateKey the private key for ES256 signing
   * @param signingCert the X.509 certificate to embed in the x5c header
   * @param type the typ header value (e.g. 'trustlist+jwt' or 'statuslist+jwt')
   * @return compact JWS string
   */
  public String signJws(
      String jsonPayload, PrivateKey privateKey, X509Certificate signingCert, String type) {
    Objects.requireNonNull(jsonPayload, "jsonPayload must not be null");
    Objects.requireNonNull(privateKey, "privateKey must not be null");
    Objects.requireNonNull(signingCert, "signingCert must not be null");

    try {
      Base64 x5c = Base64.encode(signingCert.getEncoded());
      JWSHeader.Builder headerBuilder =
          new JWSHeader.Builder(JWSAlgorithm.ES256)
              .x509CertChain(List.of(x5c));
      if (type != null && !type.isBlank()) {
        headerBuilder.type(new JOSEObjectType(type));
      }

      JWSObject jwsObject = new JWSObject(headerBuilder.build(), new Payload(jsonPayload));
      ECPrivateKey ecPrivateKey = toEcPrivateKey(privateKey);
      ECDSASigner signer = new ECDSASigner(ecPrivateKey);

      jwsObject.sign(signer);
      return jwsObject.serialize();
    } catch (CertificateEncodingException | JOSEException e) {
      throw new PkiCryptoException("Failed to create and sign JWS token", e);
    }
  }

  /**
   * Signs a Status List payload as a compact JWT with typ: statuslist+jwt, ES256, and x5c header.
   *
   * @param jsonPayload the status list JSON payload
   * @param privateKey the private key for ES256 signing
   * @param signingCert the X.509 certificate to embed in the x5c header
   * @return compact JWT string
   */
  public String signStatusListJwt(
      String jsonPayload, PrivateKey privateKey, X509Certificate signingCert) {
    return signJws(jsonPayload, privateKey, signingCert, TYPE_STATUSLIST_JWT);
  }

  /**
   * Verifies the cryptographic signature of a compact JWS token against a public key.
   *
   * @param compactJws the compact JWS token string
   * @param publicKey the public key to verify against
   * @return true if the signature is valid, false otherwise
   */
  public boolean verifyJws(String compactJws, PublicKey publicKey) {
    Objects.requireNonNull(compactJws, "compactJws must not be null");
    Objects.requireNonNull(publicKey, "publicKey must not be null");

    try {
      JWSObject jwsObject = JWSObject.parse(compactJws);
      ECPublicKey ecPublicKey = toEcPublicKey(publicKey);
      ECDSAVerifier verifier = new ECDSAVerifier(ecPublicKey);

      return jwsObject.verify(verifier);
    } catch (ParseException | JOSEException e) {
      throw new PkiCryptoException("Failed to verify JWS token", e);
    }
  }

  private ECPrivateKey toEcPrivateKey(PrivateKey privateKey) {
    if (privateKey instanceof ECPrivateKey ecKey) {
      return ecKey;
    }
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("EC");
      return (ECPrivateKey) keyFactory
          .generatePrivate(new PKCS8EncodedKeySpec(privateKey.getEncoded()));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new PkiCryptoException("Failed to convert private key to ECPrivateKey", e);
    }
  }

  private ECPublicKey toEcPublicKey(PublicKey publicKey) {
    if (publicKey instanceof ECPublicKey ecKey) {
      return ecKey;
    }
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("EC");
      return (ECPublicKey) keyFactory
          .generatePublic(new X509EncodedKeySpec(publicKey.getEncoded()));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new PkiCryptoException("Failed to convert public key to ECPublicKey", e);
    }
  }

  /**
   * Parses a compact JWS token and extracts the signing X.509 certificate from the x5c header.
   *
   * @param compactJws the compact JWS token string
   * @return Base64-encoded X.509 certificate string from header
   */
  public String extractCertificateBase64(String compactJws) {
    Objects.requireNonNull(compactJws, "compactJws must not be null");

    try {
      JWSObject jwsObject = JWSObject.parse(compactJws);
      List<Base64> x5c = jwsObject.getHeader().getX509CertChain();
      if (x5c == null || x5c.isEmpty()) {
        throw new PkiCryptoException("JWS header contains no x5c certificate chain");
      }
      return x5c.get(0).toString();
    } catch (ParseException e) {
      throw new PkiCryptoException("Failed to parse JWS header", e);
    }
  }
}
