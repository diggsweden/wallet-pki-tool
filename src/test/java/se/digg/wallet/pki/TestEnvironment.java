// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

/** Isolated filesystem fixture exercising the shipped local environment contract. */
public final class TestEnvironment {
  public static final String PASSWORD = "test-only-password";
  public static final Clock CLOCK =
      Clock.fixed(Instant.parse("2026-10-22T10:00:00Z"), ZoneOffset.UTC);

  private TestEnvironment() {}

  public static Path create(Path directory) throws IOException {
    Files.writeString(directory.resolve("password.txt"), PASSWORD + "\n");
    String yaml = Files.readString(Path.of("examples/local.yaml"))
        .replace("../.wallet-pki/local/state", "state")
        .replace("../.wallet-pki/local/bundles", "bundles")
        .replaceAll("passwordEnv: [A-Z_]+", "passwordFile: password.txt")
        .replace("file:assets/", "file:" + Path.of("examples/assets").toAbsolutePath() + "/");
    Path source = directory.resolve("environment.yaml");
    Files.writeString(source, yaml);
    return source;
  }

  public static KeyStore keyStore(Path path) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (var input = Files.newInputStream(path)) {
      store.load(input, PASSWORD.toCharArray());
    }
    return store;
  }
}
