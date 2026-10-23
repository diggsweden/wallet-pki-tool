// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import static org.assertj.core.api.Assertions.assertThat;
import com.nimbusds.jose.JWSObject;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.crypto.KeystoreManager;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.support.EcosystemFixture;
import se.digg.wallet.pki.trustlist.TrustListSigner;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.dataformat.yaml.YAMLMapper;

class WalletPkiCliComponentTest {
  @TempDir
  Path directory;
  private final StringWriter out = new StringWriter();
  private final StringWriter err = new StringWriter();
  private final YAMLMapper yaml = YAMLMapper.builder().build();

  @Test
  void root_help_lists_role_first_commands_without_reading_configuration() {
    assertThat(cli(name -> null).execute("--help")).isZero();

    assertThat(out.toString()).contains("authorities", "pid-issuer", "wallet-provider", "verifier",
        "trust-source", "ecosystem").doesNotContain("init-authorities");
    assertThat(err.toString()).isEmpty();
    assertThat(directory).isEmptyDirectory();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"pid-issuer generate", "wallet-provider generate", "verifier access generate",
          "verifier registration generate", "trust-source generate", "trust-source lote generate",
          "trust-source status-list generate", "ecosystem generate", "authorities init"})
  void every_operation_explains_its_contract_without_requiring_configuration(String command) {
    var arguments = new ArrayList<>(List.of(command.split(" ")));
    arguments.add("--help");

    assertThat(cli(name -> null).execute(arguments.toArray(String[]::new))).isZero();

    assertThat(out.toString()).contains("Usage:", "--config", "Requires", "require");
    assertThat(err.toString()).isEmpty();
    assertThat(directory).isEmptyDirectory();
  }

  @Test
  void authority_initialization_needs_only_shared_configuration() throws Exception {
    Path file = configuration();

    assertThat(run(cli(name -> null), file, "authorities init")).isZero();

    for (var role : AuthorityRole.values()) {
      assertThat(directory.resolve("state/authorities").resolve(role.directory()).resolve("ca.pem"))
          .isRegularFile();
    }
    assertThat(err.toString()).isEmpty();
  }

  @Test
  void selected_authorities_leave_unselected_material_unchanged() throws Exception {
    Path file = configuration();
    var cli = cli(name -> null);
    assertThat(run(cli, file, "authorities init pid-issuer")).isZero();
    var before = snapshot(directory.resolve("state"));

    assertThat(run(cli, file, "authorities init wallet-provider")).isZero();

    assertThat(snapshot(directory.resolve("state"))).containsAllEntriesOf(before);
    try (var paths = Files.list(directory.resolve("state/authorities"))) {
      assertThat(paths.map(path -> path.getFileName().toString()).toList())
          .containsExactlyInAnyOrder("pid-issuer", "wallet-provider");
    }
  }

  @Test
  void incomplete_authorities_fail_before_other_selected_roots_are_created() throws Exception {
    Path file = configuration();
    Path incomplete = directory.resolve("state/authorities/wallet-provider/ca.pem");
    Files.createDirectories(incomplete.getParent());
    Files.writeString(incomplete, "incomplete authority");

    assertThat(run(cli(name -> null), file, "authorities init pid-issuer wallet-provider"))
        .isEqualTo(1);

    assertThat(directory.resolve("state/authorities/pid-issuer")).doesNotExist();
    assertThat(directory.resolve("config")).doesNotExist();
    assertThat(Files.readString(incomplete)).isEqualTo("incomplete authority");
  }

  @ParameterizedTest
  @CsvSource({
      "pidIssuer, pid-issuer, PID_ISSUER_KEYSTORE_PASSWORD, certificates/issuer/pid_issuer.p12, pid_issuer",
      "walletProvider, wallet-provider, WALLET_PROVIDER_KEYSTORE_PASSWORD, certificates/wallet-provider/wallet_provider.p12, wallet_provider",
      "verifier.access, verifier access, VERIFIER_ACCESS_CERTIFICATE_KEYSTORE_PASSWORD, certificates/verifier-access-certificate/verifier-access-certificate.p12, verifier_access_certificate",
      "verifier.registration, verifier registration, VERIFIER_REGISTRATION_CERTIFICATE_KEYSTORE_PASSWORD, certificates/verifier-registration-certificate/verifier-registration-certificate.p12, registration"})
  void participant_generation_requires_only_its_own_role_and_password(String section,
      String command, String passwordName, String keystore, String alias) throws Exception {
    Path file = configuration(section);
    var lookups = new ArrayList<String>();
    var cli = cli(name -> {
      lookups.add(name);
      return name.equals(passwordName) ? "test-password" : null;
    });
    String authority = command.replace(' ', '-');
    assertThat(run(cli, file, "authorities init " + authority)).isZero();

    assertThat(run(cli, file, command + " generate")).isZero();

    assertThat(lookups).containsExactly(passwordName);
    var store = keystore(keystore);
    assertThat(Collections.list(store.aliases())).contains(alias);
    assertThat(store.getKey(alias, "test-password".toCharArray())).isNotNull();
    assertThat(store.getCertificateChain(alias)).hasSize(2);
    assertThat(out.toString()).contains("new keys", "selected files replaced");
    assertThat(err.toString()).isEmpty();
    try (var paths = Files.list(directory.resolve("state/authorities"))) {
      assertThat(paths.toList()).hasSize(1);
    }
  }

  @Test
  void configuration_can_be_supplied_before_the_role() throws Exception {
    Path file = configuration("walletProvider");
    var cli = cli(name -> "test-password");
    assertThat(run(cli, file, "authorities init wallet-provider")).isZero();

    assertThat(cli.execute("-c", file.toString(), "wallet-provider", "generate")).isZero();

    assertThat(directory.resolve("config/certificates/wallet-provider/wallet_provider.p12"))
        .isRegularFile();
  }

  @Test
  void participant_generation_preserves_unrelated_artifacts_and_authorities() throws Exception {
    Path file = initializedEcosystem();
    var before = snapshot(directory.resolve("config"));
    var roots = snapshot(directory.resolve("state"));
    var previousKey = keystore("certificates/issuer/pid_issuer.p12")
        .getCertificate("pid_issuer").getPublicKey();
    var cli = cli(name -> name.equals("PID_ISSUER_KEYSTORE_PASSWORD") ? "test-password" : null);

    assertThat(run(cli, file, "pid-issuer generate")).isZero();

    assertThat(keystore("certificates/issuer/pid_issuer.p12").getCertificate("pid_issuer")
        .getPublicKey()).isNotEqualTo(previousKey);
    var after = snapshot(directory.resolve("config"));
    for (String path : List.of("certificates/issuer/pid_issuer.p12", "pid-issuer/issuer_wrprc.jwt",
        "pid-issuer/issuer_wrprc.json")) {
      before.remove(path);
      after.remove(path);
    }
    assertThat(after).isEqualTo(before);
    assertThat(snapshot(directory.resolve("state"))).isEqualTo(roots);
  }

  @Test
  void trust_source_generation_needs_no_participant_configuration_or_private_keys()
      throws Exception {
    Path file = configuration("trustSource");
    var cli = cli(name -> name.equals("TRUST_SOURCE_KEYSTORE_PASSWORD") ? "test-password" : null);
    assertThat(run(cli, file, "authorities init")).isZero();
    deleteAuthorityPrivateKeys(false);

    assertThat(run(cli, file, "trust-source generate")).isZero();

    assertTrustDocumentsSignedBy(keystore("certificates/trust-list-signer/trust_source.p12")
        .getCertificate("trust_source").getPublicKey());
    assertThat(err.toString()).isEmpty();
  }

  @Test
  void replacing_the_trust_signer_rebuilds_both_documents_with_the_new_key() throws Exception {
    Path file = initializedEcosystem();
    var previous = keystore("certificates/trust-list-signer/trust_source.p12")
        .getCertificate("trust_source").getPublicKey();
    var before = snapshot(directory.resolve("config"));

    assertThat(run(cli(name -> "test-password"), file, "trust-source generate")).isZero();

    var current = keystore("certificates/trust-list-signer/trust_source.p12")
        .getCertificate("trust_source").getPublicKey();
    assertThat(current).isNotEqualTo(previous);
    assertTrustDocumentsSignedBy(current);
    var after = snapshot(directory.resolve("config"));
    for (String path : List.of("certificates/trust-list-signer/trust_source.p12",
        "certificates/trust-list-signer/trust_source_cert.pem",
        "trust-source/signed/trusted-entities.json", "trust-source/signed/status-list.jwt")) {
      before.remove(path);
      after.remove(path);
    }
    assertThat(after).isEqualTo(before);
  }

  @ParameterizedTest
  @CsvSource({"lote, trustSource.lote, trust-source/signed/trusted-entities.json",
      "status-list, trustSource.statusList, trust-source/signed/status-list.jwt"})
  void document_generation_requires_only_its_document_settings_and_existing_signer(String document,
      String section, String output) throws Exception {
    initializedEcosystem();
    Path file = configuration("trustSource.signer", section);
    var config = (ObjectNode) yaml.readTree(Files.readString(file));
    ((ObjectNode) config.path("trustSource").path("signer"))
        .remove(List.of("certificateFile", "commonName"));
    Files.writeString(file, yaml.writeValueAsString(config));
    deleteAuthorityPrivateKeys(true);
    if (document.equals("status-list")) {
      for (var role : AuthorityRole.values()) {
        if (role != AuthorityRole.TRUST_SOURCE) {
          Files.delete(directory.resolve("state/authorities").resolve(role.directory())
              .resolve("ca.pem"));
        }
      }
    }
    var before = snapshot(directory.resolve("config"));
    var roots = snapshot(directory.resolve("state"));
    var cli = cli(name -> name.equals("TRUST_SOURCE_KEYSTORE_PASSWORD") ? "test-password" : null);

    assertThat(run(cli, file, "trust-source " + document + " generate")).isZero();

    var after = snapshot(directory.resolve("config"));
    assertThat(JWSObject.parse(Files.readString(directory.resolve("config").resolve(output)))
        .getHeader().getX509CertChain().getFirst().decode())
        .isEqualTo(keystore("certificates/trust-list-signer/trust_source.p12")
            .getCertificate("trust_source").getEncoded());
    before.remove(output);
    after.remove(output);
    assertThat(after).isEqualTo(before);
    assertThat(snapshot(directory.resolve("state"))).isEqualTo(roots);
    assertThat(err.toString()).isEmpty();
  }

  @Test
  void ecosystem_generation_rejects_missing_role_configuration_before_reading_secrets()
      throws Exception {
    Path file = configuration("pidIssuer");
    var lookups = new ArrayList<String>();
    var cli = cli(name -> {
      lookups.add(name);
      return "test-password";
    });

    assertThat(run(cli, file, "ecosystem generate")).isEqualTo(1);

    assertThat(err.toString()).contains("walletProvider is required");
    assertThat(lookups).isEmpty();
    assertThat(directory.resolve("state")).doesNotExist();
    assertThat(directory.resolve("config")).doesNotExist();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"pid-issuer generate", "wallet-provider generate", "verifier access generate",
          "verifier registration generate", "trust-source generate", "trust-source lote generate",
          "trust-source status-list generate"})
  void missing_role_configuration_has_a_clear_error_without_writing_outputs(String command)
      throws Exception {
    Path file = configuration();

    assertThat(run(cli(name -> null), file, command)).isEqualTo(1);

    assertThat(err.toString()).contains("is required").doesNotContain("NullPointerException");
    assertThat(directory.resolve("state")).doesNotExist();
    assertThat(directory.resolve("config")).doesNotExist();
  }

  @Test
  void generation_never_creates_missing_authorities() throws Exception {
    Path file = configuration("pidIssuer");

    assertThat(run(cli(name -> "test-password"), file, "pid-issuer generate")).isEqualTo(1);

    assertThat(err.toString()).contains("authorities init");
    assertThat(directory.resolve("state")).doesNotExist();
    assertThat(directory.resolve("config")).doesNotExist();
  }

  @Test
  void missing_bulk_passwords_preserve_all_existing_outputs() throws Exception {
    Path file = initializedEcosystem();
    var before = snapshot(directory.resolve("config"));
    var roots = snapshot(directory.resolve("state"));

    assertThat(
        run(cli(name -> name.equals("TRUST_SOURCE_KEYSTORE_PASSWORD") ? null : "test-password"),
            file, "ecosystem generate"))
        .isEqualTo(1);

    assertThat(snapshot(directory.resolve("config"))).isEqualTo(before);
    assertThat(snapshot(directory.resolve("state"))).isEqualTo(roots);
    assertThat(err.toString()).contains("TRUST_SOURCE_KEYSTORE_PASSWORD");
  }

  @Test
  void missing_bulk_authorities_preserve_all_existing_outputs() throws Exception {
    Path file = initializedEcosystem();
    Files.delete(directory.resolve("state/authorities/trust-source/ca_private_key.pem"));
    var before = snapshot(directory.resolve("config"));

    assertThat(run(cli(name -> "test-password"), file, "ecosystem generate")).isEqualTo(1);

    assertThat(snapshot(directory.resolve("config"))).isEqualTo(before);
    assertThat(err.toString()).contains("Missing authority material", "trust-source");
  }

  @Test
  void a_missing_document_prerequisite_does_not_replace_the_existing_trust_signer()
      throws Exception {
    initializedEcosystem();
    Path file = configuration("trustSource.signer", "trustSource.lote");
    var before = snapshot(directory.resolve("config"));

    assertThat(run(cli(name -> "test-password"), file, "trust-source generate")).isEqualTo(1);

    assertThat(err.toString()).contains("trustSource.statusList is required");
    assertThat(snapshot(directory.resolve("config"))).isEqualTo(before);
  }

  @Test
  void document_generation_never_creates_a_missing_signer() throws Exception {
    Path file = configuration("trustSource.signer", "trustSource.lote");
    var cli = cli(name -> "test-password");
    assertThat(run(cli, file, "authorities init")).isZero();
    var before = snapshot(directory.resolve("config"));

    assertThat(run(cli, file, "trust-source lote generate")).isEqualTo(1);

    assertThat(err.toString()).contains("KeyStore file not found");
    assertThat(snapshot(directory.resolve("config"))).isEqualTo(before);
  }

  @ParameterizedTest
  @ValueSource(strings = {"pid-issuer", "verifier access", "trust-source lote", "ecosystem",
      "generate pid-issuer", "authorities init pid-issuer typo"})
  void incomplete_or_unknown_commands_never_write_outputs(String command) throws Exception {
    Path file = configuration("pidIssuer");

    assertThat(run(cli(name -> null), file, command)).isEqualTo(2);

    assertThat(directory.resolve("state")).doesNotExist();
    assertThat(directory.resolve("config")).doesNotExist();
  }

  @Test
  void missing_configuration_has_a_nonzero_exit_code() {
    assertThat(cli(name -> null).execute("pid-issuer", "generate", "-c", "missing.yaml"))
        .isEqualTo(1);

    assertThat(err.toString()).contains("Configuration file not found");
  }

  private WalletPkiCli cli(java.util.function.Function<String, String> passwords) {
    return new WalletPkiCli(new ConfigurationLoader(), new SecretResolver(passwords),
        new PrintWriter(out), new PrintWriter(err));
  }

  private int run(WalletPkiCli cli, Path file, String command) {
    var arguments = new ArrayList<>(Arrays.asList(command.split(" ")));
    arguments.addAll(List.of("-c", file.toString()));
    return cli.execute(arguments.toArray(String[]::new));
  }

  private Path initializedEcosystem() throws Exception {
    Path file = EcosystemFixture.configurationFile(directory);
    var cli = cli(name -> "test-password");
    assertThat(run(cli, file, "authorities init")).isZero();
    assertThat(run(cli, file, "ecosystem generate")).isZero();
    return file;
  }

  private Path configuration(String... sections) throws Exception {
    var source = (ObjectNode) yaml.readTree(EcosystemFixture.yaml(directory));
    var selected = source.deepCopy();
    selected.remove(List.of("pidIssuer", "walletProvider", "verifier", "trustSource"));
    var trust = source.path("trustSource");
    selected.putObject("publication")
        .put("baseUrl", trust.path("publicationBaseUrl").asString())
        .put("directory", trust.path("publicationDirectory").asString())
        .put("rootCrlFile", trust.path("rootCrlFile").asString());
    for (String section : sections) {
      String[] parts = section.split("\\.");
      if (parts.length == 1) {
        selected.set(section, source.path(section).deepCopy());
      } else {
        if (!selected.has(parts[0])) {
          selected.putObject(parts[0]);
        }
        ((ObjectNode) selected.path(parts[0])).set(parts[1], source.path(parts[0]).path(parts[1]));
      }
    }
    if (selected.has("trustSource")) {
      ((ObjectNode) selected.path("trustSource"))
          .remove(List.of("publicationBaseUrl", "publicationDirectory", "rootCrlFile"));
    }
    Path file = directory.resolve("selected.yaml");
    Files.writeString(file, yaml.writeValueAsString(selected));
    return file;
  }

  private void deleteAuthorityPrivateKeys(boolean includeSigner) throws Exception {
    for (var role : AuthorityRole.values()) {
      if (includeSigner || role != AuthorityRole.TRUST_SOURCE) {
        Files.delete(directory.resolve("state/authorities").resolve(role.directory())
            .resolve("ca_private_key.pem"));
      }
    }
  }

  private KeyStore keystore(String relative) {
    return new KeystoreManager().loadKeyStore(directory.resolve("config").resolve(relative),
        "test-password".toCharArray());
  }

  private void assertTrustDocumentsSignedBy(java.security.PublicKey key) throws Exception {
    for (String document : List.of("trusted-entities.json", "status-list.jwt")) {
      String token =
          Files.readString(directory.resolve("config/trust-source/signed").resolve(document));
      assertThat(new TrustListSigner().verifyJws(token, key)).as(document).isTrue();
    }
  }

  private Map<String, String> snapshot(Path root) throws Exception {
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
