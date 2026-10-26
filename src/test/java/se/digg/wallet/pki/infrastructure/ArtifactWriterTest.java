// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.crypto.PkiCryptoException;

class ArtifactWriterTest {
  @Test
  void root_paths_are_rejected_with_clear_errors(@TempDir Path directory) {
    Path root = directory.getFileSystem().getRootDirectories().iterator().next();
    assertThatThrownBy(() -> new ArtifactWriter().text(root, "content"))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Artifact path must name a file");
  }

  @Test
  void nested_artifacts_can_be_created_and_replaced(@TempDir Path directory) throws Exception {
    var writer = new ArtifactWriter();
    Path parent = directory.resolve("signed");
    Path file = parent.resolve("document.jwt");
    writer.text(file, "first");
    writer.text(file, "replacement");
    assertThat(Files.readString(file)).isEqualTo("replacement");
    try (var files = Files.list(parent)) {
      assertThat(files.toList()).containsExactly(file);
    }
  }
}
