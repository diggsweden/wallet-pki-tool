// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import se.digg.wallet.pki.cli.WalletPkiCli;
import se.digg.wallet.pki.config.AuthorityConfig;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.config.WalletProviderConfig;
import se.digg.wallet.pki.domain.WalletRole;
import se.digg.wallet.pki.storage.ArtifactStore;

/** Isolated shipped examples with real crypto and external password files. */
public final class TestEnvironment {
  public static final String PASSWORD = "test-only-password";
  public static final Clock CLOCK =
      Clock.fixed(Instant.parse("2026-10-22T10:00:00Z"), ZoneOffset.UTC);

  private TestEnvironment() {}

  public static Path create(Path directory) throws Exception {
    Files.writeString(directory.resolve("password.txt"), PASSWORD + "\n");
    String yaml = Files.readString(Path.of("examples/ecosystem.yaml"))
        .replace("../.wallet-pki/local/state", "state")
        .replace("../.wallet-pki/local/bundles", "bundles")
        .replaceAll("env: [A-Z_]+", "file: password.txt");
    Path source = directory.resolve("ecosystem.yaml");
    Files.writeString(source, yaml);
    return source;
  }

  public static Path sandbox(Path directory, Path ecosystem, String generation) throws Exception {
    PkiConfiguration local = new ConfigurationLoader().load(ecosystem);
    var wallet = local.walletProvider();
    Path imported = directory.resolve("imports");
    Files.createDirectories(imported);
    for (String name : List.of("ca.pem", "ca_private_key.pem", "revocation-list.pem")) {
      Files.copy(
          directory
              .resolve("state/generations/" + generation + "/authorities/wallet-provider/" + name),
          imported.resolve(name));
    }
    var authority = new AuthorityConfig(AuthorityConfig.Source.EXISTING, null,
        imported.resolve("ca.pem").toString(), imported.resolve("ca_private_key.pem").toString(),
        imported.resolve("revocation-list.pem").toString());
    var config = new PkiConfiguration(2, "sandbox", directory.resolve("sandbox-state").toString(),
        directory.resolve("sandbox-bundles").toString(), "https://trust.sandbox.example.test",
        local.organization(), null,
        new WalletProviderConfig(authority, wallet.signing(), wallet.keystorePassword()), null,
        null);
    Path path = directory.resolve("sandbox.yaml");
    Files.writeString(path, ArtifactStore.JSON.writeValueAsString(config));
    return path;
  }

  public static Path trustSandbox(Path directory, Path ecosystem, String generation)
      throws Exception {
    PkiConfiguration local = new ConfigurationLoader().load(ecosystem);
    Path roots = directory.resolve("state/generations/" + generation + "/authorities");
    var trust = local.trustSource();
    var entities = trust.lote().trustedAuthorities();
    var config =
        new PkiConfiguration(2, "sandbox-trust", directory.resolve("trust-state").toString(),
            directory.resolve("trust-bundles").toString(), local.publicationBaseUrl(),
            local.organization(),
            null, null, null, new se.digg.wallet.pki.config.TrustSourceConfig(
                new AuthorityConfig(AuthorityConfig.Source.EXISTING, null,
                    roots.resolve("trust-source/ca.pem").toString(),
                    roots.resolve("trust-source/ca_private_key.pem").toString(),
                    roots.resolve("trust-source/revocation-list.pem").toString()),
                trust.signer(),
                new se.digg.wallet.pki.config.LoteConfig(trust.lote().name(),
                    trust.lote().validityDays(),
                    new se.digg.wallet.pki.config.LoteConfig.TrustedAuthorities(
                        publicEntity(entities.pidIssuer(), roots, WalletRole.PID_ISSUER),
                        publicEntity(entities.walletProvider(), roots, WalletRole.WALLET_PROVIDER),
                        publicEntity(entities.verifierAccess(), roots, WalletRole.VERIFIER_ACCESS),
                        publicEntity(entities.verifierRegistration(), roots,
                            WalletRole.VERIFIER_REGISTRATION))),
                trust.statusList()));
    Path path = directory.resolve("sandbox-trust.yaml");
    Files.writeString(path, ArtifactStore.JSON.writeValueAsString(config));
    return path;
  }

  private static se.digg.wallet.pki.config.LoteConfig.Entity publicEntity(
      se.digg.wallet.pki.config.LoteConfig.Entity e,
      Path roots, WalletRole role) {
    return new se.digg.wallet.pki.config.LoteConfig.Entity(e.entityName(), e.serviceName(),
        e.informationUrl(),
        e.streetAddress(), roots.resolve(role.directory() + "/ca.pem").toString());
  }

  public static Result run(SecretResolver secrets, Clock clock, String workflow, String operation,
      Path source, String... roles) {
    var output = new StringWriter();
    var errors = new StringWriter();
    var args = new java.util.ArrayList<String>(
        List.of(workflow, operation, "--config", source.toString(), "--json"));
    args.addAll(List.of(roles));
    int code = new WalletPkiCli(secrets, clock, new PrintWriter(output), new PrintWriter(errors))
        .execute(args.toArray(String[]::new));
    return new Result(code, output.toString(), errors.toString());
  }


  public record Result(int code, String output, String errors) {
    public Path bundle() {
      return Path.of(ArtifactStore.JSON.readTree(output).path("bundle").asText());
    }

    public String generation() {
      return ArtifactStore.JSON.readTree(output).path("generation").asText();
    }
  }

  public static KeyStore keyStore(Path path) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (var input = Files.newInputStream(path)) {
      store.load(input, PASSWORD.toCharArray());
    }
    return store;
  }
}
