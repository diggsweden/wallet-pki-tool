// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Comparator;
import java.util.Objects;
import se.digg.wallet.pki.config.PkiConfigurationException;

/** Filesystem mechanics shared by authority initialization and artifact generation. */
public final class ArtifactFiles {
  private ArtifactFiles() {}

  public static void write(Path path, byte[] contents, boolean secret) throws IOException {
    directory(Objects.requireNonNull(path.getParent(), "Artifact file needs a parent directory"),
        secret);
    rejectSymlinks(path);
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)
        && path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      Files.createFile(path, PosixFilePermissions.asFileAttribute(
          PosixFilePermissions.fromString(secret ? "rw-------" : "rw-r--r--")));
    }
    Files.write(path, contents);
  }

  public static void directory(Path path, boolean secret) throws IOException {
    rejectSymlinks(path);
    Files.createDirectories(path);
    if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      Files.setPosixFilePermissions(path,
          PosixFilePermissions.fromString(secret ? "rwx------" : "rwxr-xr-x"));
    }
  }

  public static void rejectSymlinks(Path path) {
    for (Path ancestor = path.toAbsolutePath(); ancestor != null; ancestor = ancestor.getParent()) {
      if (Files.isSymbolicLink(ancestor)) {
        throw new PkiConfigurationException("Artifact path contains a symbolic link: " + ancestor);
      }
    }
  }

  public static void deleteTree(Path root) throws IOException {
    if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      try (var paths = Files.walk(root)) {
        for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
          Files.delete(path);
        }
      }
    }
  }
}
