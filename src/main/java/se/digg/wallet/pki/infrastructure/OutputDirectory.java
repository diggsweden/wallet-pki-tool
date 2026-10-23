// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Objects;
import se.digg.wallet.pki.config.PkiConfigurationException;

/** Builds one output directory and publishes it after all artifacts have been validated. */
public final class OutputDirectory implements AutoCloseable {
  private final Path destination;
  private final Path temporary;
  private boolean published;

  public OutputDirectory(Path destination) throws IOException {
    this.destination = destination.toAbsolutePath().normalize();
    requireAbsent(this.destination);
    ArtifactFiles.rejectSymlinks(this.destination);
    Path parent =
        Objects.requireNonNull(this.destination.getParent(), "Output needs a parent directory");
    Files.createDirectories(parent);
    temporary = Files.createTempDirectory(parent, ".wallet-pki-");
  }

  public Path path() {
    return temporary;
  }

  public Path publish() throws IOException {
    requireAbsent(destination);
    ArtifactFiles.directory(temporary, false);
    Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
    published = true;
    return destination;
  }

  public static void requireAbsent(Path destination) {
    if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
      throw new PkiConfigurationException(
          "Output already exists; choose a fresh directory: " + destination);
    }
  }

  @Override
  public void close() throws IOException {
    if (!published) {
      ArtifactFiles.deleteTree(temporary);
    }
  }
}
