// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.support;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;
import se.digg.wallet.pki.application.AuthorityProvisioner;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.application.EcosystemProvisioner;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;

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

  public static EcosystemProvisioner provisioner() {
    return new EcosystemProvisioner(new SecretResolver(key -> "test-password"));
  }

  public static PrintWriter quiet() {
    return new PrintWriter(new StringWriter());
  }
}
