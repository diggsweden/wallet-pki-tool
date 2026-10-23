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

class OutputDirectoryIntegrationTest {
  @TempDir
  Path directory;

  @Test
  void unpublished_files_are_removed_when_generation_fails() throws Exception {
    Path output = directory.resolve("output");
    Path temporary;
    try (var staging = new OutputDirectory(output)) {
      temporary = staging.path();
      Files.writeString(temporary.resolve("partial.txt"), "partial");
    }

    assertThat(output).doesNotExist();
    assertThat(temporary).doesNotExist();
  }

  @Test
  void publication_exposes_the_complete_directory() throws Exception {
    Path output = directory.resolve("output");
    try (var staging = new OutputDirectory(output)) {
      Files.writeString(staging.path().resolve("complete.txt"), "complete");

      assertThat(staging.publish()).isEqualTo(output);
    }

    assertThat(Files.readString(output.resolve("complete.txt"))).isEqualTo("complete");
  }

  @Test
  void concurrent_destination_creation_never_overwrites_existing_files() throws Exception {
    Path output = directory.resolve("output");
    Path temporary;
    try (var staging = new OutputDirectory(output)) {
      temporary = staging.path();
      Files.writeString(temporary.resolve("new.txt"), "new");
      Files.createDirectory(output);
      Files.writeString(output.resolve("existing.txt"), "existing");

      assertThatThrownBy(staging::publish).hasMessageContaining("Output already exists");
    }

    assertThat(Files.readString(output.resolve("existing.txt"))).isEqualTo("existing");
    assertThat(output.resolve("new.txt")).doesNotExist();
    assertThat(temporary).doesNotExist();
  }
}
