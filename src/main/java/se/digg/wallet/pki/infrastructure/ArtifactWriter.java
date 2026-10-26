// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.crypto.PkiCryptoException;

/** Writes public artifacts with mode 0644 on POSIX filesystems, replacing them atomically. */
public final class ArtifactWriter {
  private final EcKeyGenerator pem = new EcKeyGenerator();

  public void text(Path path, String content) {
    Path temporary = null;
    try {
      Path absolute = path.toAbsolutePath();
      Path parent = absolute.getParent();
      if (parent == null) {
        throw new PkiCryptoException("Artifact path must name a file: " + path);
      }
      Files.createDirectories(parent);
      temporary = Files.createTempFile(parent, ".wallet-pki-", ".tmp");
      Files.writeString(temporary, content);
      if (Files.getFileAttributeView(temporary, PosixFileAttributeView.class) != null) {
        Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rw-r--r--"));
      }
      Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      throw new PkiCryptoException("Cannot write artifact: " + path, e);
    } finally {
      if (temporary != null) {
        try {
          Files.deleteIfExists(temporary);
        } catch (IOException e) {
          throw new PkiCryptoException("Cannot remove temporary artifact: " + temporary, e);
        }
      }
    }
  }

  public void pem(Path path, Object value) {
    text(path, pem.toPemString(value));
  }
}
