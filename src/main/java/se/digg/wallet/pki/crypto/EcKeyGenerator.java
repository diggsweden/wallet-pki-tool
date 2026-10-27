// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.crypto;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
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

  private final SecureRandom secureRandom = new SecureRandom();

  public KeyPair generateKeyPair() {
    try {
      KeyPairGenerator keyGen =
          KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
      ECGenParameterSpec ecSpec = new ECGenParameterSpec(DEFAULT_CURVE);
      keyGen.initialize(ecSpec, secureRandom);
      return keyGen.generateKeyPair();
    } catch (NoSuchAlgorithmException
        | NoSuchProviderException
        | InvalidAlgorithmParameterException e) {
      throw new PkiCryptoException("Failed to generate EC key pair for curve: " + DEFAULT_CURVE, e);
    }
  }

  /** Encodes a cryptographic object (e.g. PrivateKey, PublicKey, Certificate) to PEM string. */
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

  /** Writes a private key to disk in PEM format with mode 0644 on POSIX filesystems. */
  public void writePrivateKeyPem(PrivateKey privateKey, Path outputPath) {
    try {
      Path parent = outputPath.getParent();
      if (parent != null) {
        Files.createDirectories(parent);
      }
      String pem = toPemString(privateKey);
      Files.writeString(outputPath, pem, StandardCharsets.UTF_8);

      if (Files.getFileAttributeView(outputPath, PosixFileAttributeView.class) != null) {
        Files.setPosixFilePermissions(outputPath, PosixFilePermissions.fromString("rw-r--r--"));
      }
    } catch (IOException e) {
      throw new PkiCryptoException("Failed to write private key PEM file to: " + outputPath, e);
    }
  }

  /** Writes any PEM-encodable object to disk. */
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

  /** Reads a private key from a PEM file on disk. */
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

  /** Reads a private key from a PEM string. */
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
