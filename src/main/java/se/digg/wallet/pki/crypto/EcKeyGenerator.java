// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

/**
 * Utility for generating and reading/writing Elliptic Curve (EC P-256 / secp256r1) key pairs in PEM
 * format using Bouncy Castle.
 */
public class EcKeyGenerator {

  public static final String DEFAULT_CURVE = "secp256r1";

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private final SecureRandom secureRandom;

  /** Default constructor using standard SecureRandom. */
  public EcKeyGenerator() {
    this(new SecureRandom());
  }

  /**
   * Constructor with explicit SecureRandom.
   *
   * @param secureRandom the secure random instance
   */
  public EcKeyGenerator(SecureRandom secureRandom) {
    this.secureRandom = secureRandom;
  }

  /**
   * Generates a new EC P-256 (secp256r1) key pair.
   *
   * @return newly generated KeyPair
   * @throws PkiCryptoException if key generation fails
   */
  public KeyPair generateKeyPair() {
    return generateKeyPair(DEFAULT_CURVE);
  }

  /**
   * Generates a new EC key pair for the specified curve name.
   *
   * @param curveName the EC curve name (e.g. "secp256r1" or "prime256v1")
   * @return newly generated KeyPair
   * @throws PkiCryptoException if key generation fails
   */
  public KeyPair generateKeyPair(String curveName) {
    try {
      KeyPairGenerator keyGen =
          KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
      ECGenParameterSpec ecSpec = new ECGenParameterSpec(curveName);
      keyGen.initialize(ecSpec, secureRandom);
      return keyGen.generateKeyPair();
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | InvalidAlgorithmParameterException e) {
      throw new PkiCryptoException("Failed to generate EC key pair for curve: " + curveName, e);
    }
  }

  /**
   * Encodes a cryptographic object (e.g. PrivateKey, PublicKey, Certificate) to PEM string.
   *
   * @param object the object to encode
   * @return PEM formatted string
   * @throws PkiCryptoException if encoding fails
   */
  public String toPemString(Object object) {
    try (StringWriter sw = new StringWriter();
        JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
      pemWriter.writeObject(object);
      pemWriter.flush();
      return sw.toString();
    } catch (IOException e) {
      throw new PkiCryptoException("Failed to encode object to PEM format", e);
    }
  }

  /**
   * Writes a private key to disk in PEM format with owner-only permissions (0600 / rw-------).
   *
   * @param privateKey the private key
   * @param outputPath the destination file path
   * @throws PkiCryptoException if writing fails
   */
  public void writePrivateKeyPem(PrivateKey privateKey, Path outputPath) {
    try {
      Path parent = outputPath.getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
      String pem = toPemString(privateKey);
      Files.writeString(outputPath, pem, StandardCharsets.UTF_8);

      // Enforce owner-only permissions (0600) on POSIX filesystems to protect private keys
      if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
        Files.setPosixFilePermissions(outputPath, perms);
      }
    } catch (IOException e) {
      throw new PkiCryptoException("Failed to write private key PEM file to: " + outputPath, e);
    }
  }

  /**
   * Writes a public key to disk in PEM format.
   *
   * @param publicKey the public key
   * @param outputPath the destination file path
   * @throws PkiCryptoException if writing fails
   */
  public void writePublicKeyPem(PublicKey publicKey, Path outputPath) {
    writePemFile(publicKey, outputPath);
  }

  /**
   * Writes any PEM-encodable object to disk.
   *
   * @param object the object to write
   * @param outputPath the destination file path
   */
  public void writePemFile(Object object, Path outputPath) {
    try {
      Path parent = outputPath.getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
      String pem = toPemString(object);
      Files.writeString(outputPath, pem, StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new PkiCryptoException("Failed to write PEM file to: " + outputPath, e);
    }
  }

  /**
   * Reads a private key from a PEM file on disk.
   *
   * @param inputPath the path to the PEM file
   * @return the parsed PrivateKey
   * @throws PkiCryptoException if reading or parsing fails
   */
  public PrivateKey readPrivateKeyPem(Path inputPath) {
    try {
      if (!Files.exists(inputPath)) {
        throw new PkiCryptoException("Private key file not found: " + inputPath);
      }
      String content = Files.readString(inputPath, StandardCharsets.UTF_8);
      return readPrivateKeyPem(content);
    } catch (IOException e) {
      throw new PkiCryptoException("Failed to read private key file from: " + inputPath, e);
    }
  }

  /**
   * Reads a private key from a PEM string.
   *
   * @param pemContent the PEM string content
   * @return the parsed PrivateKey
   * @throws PkiCryptoException if parsing fails
   */
  public PrivateKey readPrivateKeyPem(String pemContent) {
    try (PEMParser parser = new PEMParser(new StringReader(pemContent))) {
      Object parsed = parser.readObject();
      if (parsed == null) {
        throw new PkiCryptoException("No PEM object found in provided content");
      }
      JcaPEMKeyConverter converter =
          new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
      if (parsed instanceof PEMKeyPair pemKeyPair) {
        return converter.getKeyPair(pemKeyPair).getPrivate();
      } else if (parsed instanceof PrivateKeyInfo privateKeyInfo) {
        return converter.getPrivateKey(privateKeyInfo);
      } else {
        throw new PkiCryptoException(
            "Unsupported PEM private key format: " + parsed.getClass().getName());
      }
    } catch (IOException | RuntimeException e) {
      if (e instanceof PkiCryptoException pce) {
        throw pce;
      }
      throw new PkiCryptoException("Failed to parse PEM private key", e);
    }
  }
}
