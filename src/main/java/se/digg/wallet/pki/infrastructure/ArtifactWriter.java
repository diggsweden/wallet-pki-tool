// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.crypto.PkiCryptoException;

/** Output failures are fatal. A complete artifact replaces its previous version atomically. */
public final class ArtifactWriter {
  private final EcKeyGenerator pem = new EcKeyGenerator();

  public void text(Path path, String content) {
    Path temporary = null;
    try {
      Path absolute = path.toAbsolutePath();
      Files.createDirectories(absolute.getParent());
      temporary = Files.createTempFile(absolute.getParent(), ".wallet-pki-", ".tmp");
      Files.writeString(temporary, content);
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
