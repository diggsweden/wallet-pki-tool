// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import se.digg.wallet.pki.storage.ArtifactStore;

/** Writes only into an isolated generation; publication belongs to ArtifactStore. */
public final class ArtifactWriter {
  public void text(Path path, String content) {
    try {
      ArtifactStore.write(path, content.getBytes(StandardCharsets.UTF_8), false);
    } catch (java.io.IOException e) {
      throw new PkiCryptoException("Cannot write artifact: " + path, e);
    }
  }

  public void pem(Path path, Object value) {
    text(path, new EcKeyGenerator().toPemString(value));
  }
}
