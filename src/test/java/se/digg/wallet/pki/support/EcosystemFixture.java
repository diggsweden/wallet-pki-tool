// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.support;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Map;
import java.util.TreeMap;
import se.digg.wallet.pki.application.AuthorityProvisioner;
import se.digg.wallet.pki.application.WalletServicesPkiGenerator;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.domain.AuthorityRole;

/** Real configuration and crypto fixture, isolated under a JUnit temporary directory. */
public final class EcosystemFixture {
  private EcosystemFixture() {}

  public static String yaml(Path directory) throws IOException {
    return Files.readString(Path.of("src/test/resources/test-ecosystem.yaml"))
        .replace("./target/test-pki-state", directory.resolve("state").toString())
        .replace("./target/test-ecosystem", directory.resolve("config").toString());
  }

  public static Path configurationFile(Path directory) throws IOException {
    Path file = directory.resolve("ecosystem.yaml");
    Files.writeString(file, yaml(directory));
    return file;
  }

  public static PkiConfiguration configuration(Path directory) throws IOException {
    return new ConfigurationLoader().load(configurationFile(directory));
  }

  public static void initializeAuthorities(PkiConfiguration config) {
    new AuthorityProvisioner().initialize(config, EnumSet.allOf(AuthorityRole.class), quiet());
  }

  public static WalletServicesPkiGenerator provisioner() {
    return new WalletServicesPkiGenerator(new SecretResolver(key -> "test-password"));
  }

  public static PrintWriter quiet() {
    return new PrintWriter(Writer.nullWriter());
  }

  public static Map<String, String> snapshot(Path root) throws IOException {
    Map<String, String> files = new TreeMap<>();
    try (var paths = Files.walk(root)) {
      for (Path path : paths.filter(Files::isRegularFile).toList()) {
        files.put(root.relativize(path).toString(),
            Base64.getEncoder().encodeToString(Files.readAllBytes(path)));
      }
    }
    return files;
  }
}
