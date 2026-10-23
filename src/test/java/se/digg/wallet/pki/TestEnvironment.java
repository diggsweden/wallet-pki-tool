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
import se.digg.wallet.pki.config.LoteConfig;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.config.TrustSourceConfig;
import se.digg.wallet.pki.config.WalletProviderConfig;
import se.digg.wallet.pki.domain.WalletRole;
import tools.jackson.databind.json.JsonMapper;

/** Isolated inputs and consumer outputs with real crypto and password files. */
public final class TestEnvironment {
  public static final String PASSWORD = "test-only-password";
  public static final Clock CLOCK =
      Clock.fixed(Instant.parse("2026-10-22T10:00:00Z"), ZoneOffset.UTC);
  public static final JsonMapper JSON = JsonMapper.builder().build();

  private TestEnvironment() {}

  public static Path create(Path directory) throws Exception {
    Files.writeString(directory.resolve("password.txt"), PASSWORD + "\n");
    String yaml = Files.readString(Path.of("examples/managed-authorities.yaml"))
        .replace("../.wallet-pki/authorities", "authorities")
        .replace("../generated/participants", "generated")
        .replaceAll("env: [A-Z_]+", "file: password.txt");
    Path source = directory.resolve("participants.yaml");
    Files.writeString(source, yaml);
    return source;
  }

  public static Path importedWalletProvider(Path directory, Path source) throws Exception {
    var local = new ConfigurationLoader().load(source);
    Path supplied = directory.resolve("inputs");
    Files.createDirectories(supplied);
    for (String name : List.of("ca.pem", "ca_private_key.pem", "revocation-list.pem")) {
      Files.copy(directory.resolve("authorities/wallet-provider/" + name), supplied.resolve(name));
    }
    var wallet = local.walletProvider();
    var authority = new AuthorityConfig(AuthorityConfig.Source.EXISTING, null,
        supplied.resolve("ca.pem").toString(), supplied.resolve("ca_private_key.pem").toString(),
        supplied.resolve("revocation-list.pem").toString());
    var config = new PkiConfiguration(directory.resolve("unused-authorities").toString(),
        directory.resolve("imported-output").toString(), "https://trust.example.test",
        local.organization(), null,
        new WalletProviderConfig(authority, wallet.signing(), wallet.keystorePassword()), null,
        null);
    return save(directory.resolve("imported.yaml"), config);
  }

  public static Path importedTrustSource(Path directory, Path source) throws Exception {
    var local = new ConfigurationLoader().load(source);
    var trust = local.trustSource();
    Path roots = directory.resolve("authorities");
    var a = trust.lote().trustedAuthorities();
    var config = new PkiConfiguration(directory.resolve("unused-authorities").toString(),
        directory.resolve("trust-output").toString(), local.publicationBaseUrl(),
        local.organization(), null, null, null,
        new TrustSourceConfig(new AuthorityConfig(AuthorityConfig.Source.EXISTING, null,
            roots.resolve("trust-source/ca.pem").toString(),
            roots.resolve("trust-source/ca_private_key.pem").toString(),
            roots.resolve("trust-source/revocation-list.pem").toString()), trust.signer(),
            new LoteConfig(trust.lote().name(), trust.lote().sequenceNumber(),
                trust.lote().validityDays(),
                new LoteConfig.TrustedAuthorities(
                    entity(a.pidIssuer(), roots, WalletRole.PID_ISSUER),
                    entity(a.walletProvider(), roots, WalletRole.WALLET_PROVIDER),
                    entity(a.verifierAccess(), roots, WalletRole.VERIFIER_ACCESS),
                    entity(a.verifierRegistration(), roots, WalletRole.VERIFIER_REGISTRATION))),
            trust.statusList()));
    return save(directory.resolve("trust.yaml"), config);
  }

  private static LoteConfig.Entity entity(LoteConfig.Entity e, Path roots, WalletRole role) {
    return new LoteConfig.Entity(e.entityName(), e.serviceName(), e.informationUrl(),
        e.streetAddress(), roots.resolve(role.directory() + "/ca.pem").toString());
  }

  public static Path save(Path path, PkiConfiguration config) throws Exception {
    Files.writeString(path, JSON.writeValueAsString(config));
    return path;
  }

  public static Result run(String command, Path source, String... arguments) {
    return run(new SecretResolver(), command, source, arguments);
  }

  public static Result run(SecretResolver secrets, String command, Path source,
      String... arguments) {
    var output = new StringWriter();
    var errors = new StringWriter();
    var args =
        new java.util.ArrayList<String>(List.of(command, "--config", source.toString(), "--json"));
    args.addAll(List.of(arguments));
    int code = new WalletPkiCli(secrets, CLOCK, new PrintWriter(output), new PrintWriter(errors))
        .execute(args.toArray(String[]::new));
    return new Result(code, output.toString(), errors.toString());
  }

  public record Result(int code, String output, String errors) {
    public Path directory() {
      return Path.of(JSON.readTree(output).path("directory").asText());
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
