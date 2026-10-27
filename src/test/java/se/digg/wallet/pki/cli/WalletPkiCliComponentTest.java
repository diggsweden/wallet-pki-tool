// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static se.digg.wallet.pki.support.EcosystemFixture.snapshot;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.SignedJWT;
import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;
import java.util.zip.InflaterInputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.KeystoreManager;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.infrastructure.ArtifactWriter;
import se.digg.wallet.pki.support.EcosystemFixture;
import se.digg.wallet.pki.trustlist.LoteGenerator;
import se.digg.wallet.pki.trustlist.TrustListSigner;
import tools.jackson.databind.JsonNode;
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

    assertThat(out.toString())
        .contains("authorities", "pid-issuer", "wallet-attestation-issuer", "verifier",
            "trust-source", "ecosystem")
        .doesNotContain("init-authorities");
    assertThat(err.toString()).isEmpty();
    assertThat(directory).isEmptyDirectory();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"pid-issuer generate", "wallet-attestation-issuer generate",
          "verifier access generate",
          "verifier registration generate", "trust-source generate", "trust-source lote generate",
          "ecosystem generate", "authorities init"})
  void every_operation_explains_its_contract_without_requiring_configuration(String command) {
    var arguments = new ArrayList<>(List.of(command.split(" ")));
    arguments.add("--help");

    assertThat(cli(name -> null).execute(arguments.toArray(String[]::new))).isZero();

    assertThat(out.toString()).contains("Usage:", "--config").containsIgnoringCase("require");
    assertThat(err.toString()).isEmpty();
    assertThat(directory).isEmptyDirectory();
  }

  @Test
  void trust_source_help_has_no_separate_status_list_command() {
    assertThat(cli(name -> null).execute("trust-source", "--help")).isZero();

    assertThat(out.toString()).contains("generate", "lote").doesNotContain("status-list");
    assertThat(err.toString()).isEmpty();
    assertThat(directory).isEmptyDirectory();
  }

  @Test
  void authority_initialization_needs_only_shared_configuration() throws Exception {
    Path file = configuration();

    assertThat(run(cli(name -> null), file, "authorities init")).isZero();

    for (var role : AuthorityRole.values()) {
      assertThat(directory.resolve("state/ca").resolve(role.directory()).resolve("ca.pem"))
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

    assertThat(run(cli, file, "authorities init wallet-attestation-issuer")).isZero();

    assertThat(snapshot(directory.resolve("state"))).containsAllEntriesOf(before);
    Path caDirectory = directory.resolve("state/ca");
    try (var paths = Files.list(caDirectory)) {
      assertThat(paths.map(caDirectory::relativize).map(Path::toString).toList())
          .containsExactlyInAnyOrder("pid-issuer", "wallet-attestation-issuer");
    }
  }

  @Test
  void selected_authorities_need_only_their_own_common_name() throws Exception {
    Path file = configuration();
    var config = (ObjectNode) yaml.readTree(Files.readString(file));
    var authority = config.path("authorities").path("walletAttestationIssuer").deepCopy();
    config.putObject("authorities").set("walletAttestationIssuer", authority);
    Files.writeString(file, yaml.writeValueAsString(config));

    assertThat(run(cli(name -> null), file, "authorities init wallet-attestation-issuer")).isZero();

    assertThat(directory.resolve("state/ca/wallet-attestation-issuer/ca.pem"))
        .isRegularFile();
    assertThat(directory.resolve("state/ca/pid-issuer")).doesNotExist();
    assertThat(err.toString()).isEmpty();
  }

  @Test
  void missing_selected_authority_settings_fail_before_any_authority_is_created() throws Exception {
    Path file = configuration();
    var config = (ObjectNode) yaml.readTree(Files.readString(file));
    ((ObjectNode) config.path("authorities")).remove("walletAttestationIssuer");
    Files.writeString(file, yaml.writeValueAsString(config));

    assertThat(
        run(cli(name -> null), file, "authorities init pid-issuer wallet-attestation-issuer"))
        .isEqualTo(1);

    assertThat(err.toString()).contains("authorities.walletAttestationIssuer is required");
    assertThat(directory.resolve("state")).doesNotExist();
    assertThat(directory.resolve("config")).doesNotExist();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"authorities init", "wallet-attestation-issuer generate",
          "trust-source lote generate",
          "ecosystem generate"})
  void changed_ca_common_names_preserve_existing_authorities_and_outputs(String command)
      throws Exception {
    Path file = initializedEcosystem();
    var config = (ObjectNode) yaml.readTree(Files.readString(file));
    ((ObjectNode) config.path("authorities").path("walletAttestationIssuer"))
        .put("commonName", "Changed Provider CA");
    Files.writeString(file, yaml.writeValueAsString(config));
    var before = snapshot(directory.resolve("config"));
    var roots = snapshot(directory.resolve("state"));

    assertThat(run(cli(name -> "test-password"), file, command)).isEqualTo(1);

    assertThat(err.toString()).contains("subject differs", "wallet-attestation-issuer");
    assertThat(snapshot(directory.resolve("config"))).isEqualTo(before);
    assertThat(snapshot(directory.resolve("state"))).isEqualTo(roots);
  }

  @Test
  void incomplete_authorities_fail_before_other_selected_roots_are_created() throws Exception {
    Path file = configuration();
    Path authorityDirectory = directory.resolve("state/ca/wallet-attestation-issuer");
    Files.createDirectories(authorityDirectory);
    Path incomplete = authorityDirectory.resolve("ca.pem");
    Files.writeString(incomplete, "incomplete authority");

    assertThat(
        run(cli(name -> null), file, "authorities init pid-issuer wallet-attestation-issuer"))
        .isEqualTo(1);

    assertThat(directory.resolve("state/ca/pid-issuer")).doesNotExist();
    assertThat(directory.resolve("config")).doesNotExist();
    assertThat(Files.readString(incomplete)).isEqualTo("incomplete authority");
  }

  @ParameterizedTest
  @MethodSource("participants")
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
    try (var paths = Files.list(directory.resolve("state/ca"))) {
      assertThat(paths.toList()).hasSize(1);
    }
  }

  @Test
  void configuration_can_be_supplied_before_the_role() throws Exception {
    Path file = configuration("walletAttestationIssuer");
    var cli = cli(name -> "test-password");
    assertThat(run(cli, file, "authorities init wallet-attestation-issuer")).isZero();

    assertThat(cli.execute("-c", file.toString(), "wallet-attestation-issuer", "generate"))
        .isZero();

    assertThat(directory
        .resolve("config/certificates/wallet-attestation-issuer/wallet_attestation_issuer.p12"))
        .isRegularFile();
  }

  @Test
  void participant_generation_preserves_unrelated_artifacts_and_authorities() throws Exception {
    Path file = initializedEcosystem();
    var before = snapshot(directory.resolve("config"));
    final var roots = snapshot(directory.resolve("state"));
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
    final var before = snapshot(directory.resolve("config"));

    assertThat(run(cli(name -> "test-password"), file, "trust-source generate")).isZero();

    var current = keystore("certificates/trust-list-signer/trust_source.p12")
        .getCertificate("trust_source").getPublicKey();
    assertThat(current).isNotEqualTo(previous);
    assertTrustDocumentsSignedBy(current);
    for (String document : List.of("trusted-entities.json", "status-list.jwt")) {
      String token = Files.readString(directory.resolve("config/trust-source/signed")
          .resolve(document));
      assertThat(new TrustListSigner().verifyJws(token, previous)).as(document).isFalse();
    }
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
  @ValueSource(strings = {"https://example.se/trust", "https://example.se/trust/"})
  void the_status_fixture_uses_shared_distribution_settings_and_lote_validity(String baseUrl)
      throws Exception {
    Path file = configuration("trustSource.signer", "trustSource.lote");
    var config = (ObjectNode) yaml.readTree(Files.readString(file));
    var distribution = (ObjectNode) config.path("caDistribution");
    distribution.put("baseUrl", baseUrl);
    distribution.put("directory", "public-trust");
    ((ObjectNode) config.path("trustSource").path("lote")).put("validityDays", 7);
    Files.writeString(file, yaml.writeValueAsString(config));
    var cli = cli(name -> "test-password");
    assertThat(run(cli, file, "authorities init")).isZero();
    Instant before = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);

    assertThat(run(cli, file, "trust-source generate")).isZero();

    var token = SignedJWT.parse(Files.readString(
        directory.resolve("config/public-trust/signed/status-list.jwt")));
    var certificate = keystore("certificates/trust-list-signer/trust_source.p12")
        .getCertificate("trust_source");
    assertThat(token.getHeader().getType().toString()).isEqualTo("statuslist+jwt");
    assertThat(token.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
    assertThat(token.getHeader().getX509CertChain()).hasSize(1);
    assertThat(token.getHeader().getX509CertChain().getFirst().decode())
        .isEqualTo(certificate.getEncoded());
    assertThat(new TrustListSigner().verifyJws(token.serialize(), certificate.getPublicKey()))
        .isTrue();
    var claims = token.getJWTClaimsSet();
    assertThat(claims.getSubject()).isEqualTo("https://example.se/trust/signed/status-list.jwt");
    assertThat(claims.getIssuer()).isEqualTo(claims.getSubject());
    assertThat(claims.getIssueTime().toInstant()).isBetween(before, Instant.now());
    assertThat(claims.getExpirationTime().toInstant())
        .isEqualTo(claims.getIssueTime().toInstant().plus(Duration.ofDays(7)));
    var status = yaml.readTree(token.getPayload().toString()).path("status_list");
    assertThat(status.path("bits").asInt()).isEqualTo(1);
    byte[] compressed = Base64.getUrlDecoder().decode(status.path("lst").asString());
    try (var entries = new InflaterInputStream(new ByteArrayInputStream(compressed))) {
      assertThat(entries.readAllBytes()).isEqualTo(new byte[1024]);
    }
    assertThat(directory.resolve("config/trust-source/signed/status-list.jwt")).doesNotExist();
    assertThat(err.toString()).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void local_cas_and_certificate_files_can_share_lote_types(boolean absolutePath)
      throws Exception {
    Path file = initializedEcosystem();
    var external = new CertificateAuthorityManager().createAuthority("external", "Previous PID CA");
    Path certificateFile = directory.resolve("previous-pid-ca.pem");
    new ArtifactWriter().pem(certificateFile, external.certificate());
    var config = (ObjectNode) yaml.readTree(Files.readString(file));
    var entries = config.path("trustSource").path("lote").path("trustedAuthorities")
        .withArray("pidIssuer");
    var previous = ((ObjectNode) entries.get(0)).deepCopy();
    previous.put("certificateFile", absolutePath ? certificateFile.toString()
        : Path.of("").toAbsolutePath().relativize(certificateFile).toString());
    previous.put("entityName", "Previous PID Provider");
    entries.add(previous);
    Files.writeString(file, yaml.writeValueAsString(config));
    final var roots = snapshot(directory.resolve("state"));

    assertThat(run(cli(name -> "test-password"), file, "trust-source lote generate")).isZero();

    var pidEntries = new ArrayList<JsonNode>();
    for (var entry : loteEntries()) {
      if (entry.at("/TrustedEntityServices/0/ServiceInformation/ServiceTypeIdentifier").asString()
          .equals(LoteGenerator.SVC_TYPE_PID_ISSUANCE)) {
        pidEntries.add(entry);
      }
    }
    assertThat(loteEntries().size()).isEqualTo(5);
    assertThat(pidEntries).hasSize(2);
    var local = new CertificateAuthorityManager()
        .readCertificatePem(directory.resolve("state/ca/pid-issuer/ca.pem"));
    assertThat(Base64.getDecoder().decode(pidEntries.get(0)
        .at("/TrustedEntityServices/0/ServiceInformation/"
            + "ServiceDigitalIdentity/X509Certificates/0/val")
        .asString())).isEqualTo(local.getEncoded());
    assertThat(Base64.getDecoder().decode(pidEntries.get(1)
        .at("/TrustedEntityServices/0/ServiceInformation/"
            + "ServiceDigitalIdentity/X509Certificates/0/val")
        .asString())).isEqualTo(external.certificate().getEncoded());
    assertThat(pidEntries.get(1).at("/TrustedEntityInformation/TEName/0/value").asString())
        .isEqualTo("Previous PID Provider");
    assertThat(snapshot(directory.resolve("state"))).isEqualTo(roots);
    assertThat(err.toString()).isEmpty();
  }

  @Test
  void certificate_file_overrides_need_no_local_participant_authorities() throws Exception {
    Path file = initializedEcosystem();
    var external = new CertificateAuthorityManager().createAuthority("external", "External CA");
    Path certificateFile = directory.resolve("external-ca.pem");
    new ArtifactWriter().pem(certificateFile, external.certificate());
    var config = (ObjectNode) yaml.readTree(Files.readString(file));
    var lote = (ObjectNode) config.path("trustSource").path("lote");
    var entry = ((ObjectNode) lote.path("trustedAuthorities").path("pidIssuer").get(0)).deepCopy();
    entry.put("certificateFile", certificateFile.toString());
    lote.putObject("trustedAuthorities").putArray("pidIssuer").add(entry);
    Files.writeString(file, yaml.writeValueAsString(config));
    deleteAuthorityPrivateKeys(true);
    for (var role : AuthorityRole.values()) {
      if (role != AuthorityRole.TRUST_SOURCE) {
        Files.delete(
            directory.resolve("state/ca").resolve(role.directory()).resolve("ca.pem"));
      }
    }

    assertThat(run(cli(name -> "test-password"), file, "trust-source lote generate")).isZero();

    var entries = loteEntries();
    assertThat(entries.size()).isEqualTo(1);
    assertThat(Base64.getDecoder().decode(entries.get(0)
        .at("/TrustedEntityServices/0/ServiceInformation/"
            + "ServiceDigitalIdentity/X509Certificates/0/val")
        .asString())).isEqualTo(external.certificate().getEncoded());
    assertThat(err.toString()).isEmpty();
  }

  @ParameterizedTest
  @CsvSource({"missing, trust-source generate", "malformed, trust-source generate",
      "leaf, trust-source generate", "missing, trust-source lote generate",
      "malformed, trust-source lote generate", "leaf, trust-source lote generate",
      "missing, ecosystem generate", "malformed, ecosystem generate", "leaf, ecosystem generate"})
  void invalid_certificate_overrides_preserve_existing_outputs(String kind, String command)
      throws Exception {
    Path file = initializedEcosystem();
    Path certificateFile = directory.resolve("invalid-ca.pem");
    String expectedError = "Certificate file not found";
    if (kind.equals("malformed")) {
      Files.writeString(certificateFile, "not a certificate");
      expectedError = "No PEM object";
    } else if (kind.equals("leaf")) {
      new ArtifactWriter().pem(certificateFile,
          keystore("certificates/trust-list-signer/trust_source.p12")
              .getCertificate("trust_source"));
      expectedError = "CA certificate";
    }
    var config = (ObjectNode) yaml.readTree(Files.readString(file));
    ((ObjectNode) config.path("trustSource").path("lote").path("trustedAuthorities")
        .path("pidIssuer").get(0)).put("certificateFile", certificateFile.toString());
    Files.writeString(file, yaml.writeValueAsString(config));
    var before = snapshot(directory.resolve("config"));

    assertThat(run(cli(name -> "test-password"), file, command)).isEqualTo(1);

    assertThat(snapshot(directory.resolve("config"))).isEqualTo(before);
    assertThat(err.toString()).contains(expectedError);
  }

  @Test
  void lote_generation_requires_only_lote_settings_and_existing_signer() throws Exception {
    initializedEcosystem();
    Path file = configuration("trustSource.signer", "trustSource.lote");
    final String output = "trust-source/signed/trusted-entities.json";
    var config = (ObjectNode) yaml.readTree(Files.readString(file));
    ((ObjectNode) config.path("trustSource").path("signer"))
        .remove(List.of("certificateFile", "commonName"));
    Files.writeString(file, yaml.writeValueAsString(config));
    deleteAuthorityPrivateKeys(true);
    var before = snapshot(directory.resolve("config"));
    final var roots = snapshot(directory.resolve("state"));
    var cli = cli(name -> name.equals("TRUST_SOURCE_KEYSTORE_PASSWORD") ? "test-password" : null);

    assertThat(run(cli, file, "trust-source lote generate")).isZero();

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

    assertThat(err.toString()).contains("walletAttestationIssuer is required");
    assertThat(lookups).isEmpty();
    assertThat(directory.resolve("state")).doesNotExist();
    assertThat(directory.resolve("config")).doesNotExist();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"pid-issuer generate", "wallet-attestation-issuer generate",
          "verifier access generate",
          "verifier registration generate", "trust-source generate", "trust-source lote generate"})
  void missing_role_configuration_reports_clear_errors_without_writing_outputs(String command)
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
    Files.delete(directory.resolve("state/ca/trust-source/ca_private_key.pem"));
    var before = snapshot(directory.resolve("config"));

    assertThat(run(cli(name -> "test-password"), file, "ecosystem generate")).isEqualTo(1);

    assertThat(snapshot(directory.resolve("config"))).isEqualTo(before);
    assertThat(err.toString()).contains("Missing authority material", "trust-source");
  }

  @Test
  void missing_document_prerequisites_preserve_existing_trust_signers()
      throws Exception {
    initializedEcosystem();
    Path file = configuration("trustSource.signer");
    var before = snapshot(directory.resolve("config"));

    assertThat(run(cli(name -> "test-password"), file, "trust-source generate")).isEqualTo(1);

    assertThat(err.toString()).contains("trustSource.lote is required");
    assertThat(snapshot(directory.resolve("config"))).isEqualTo(before);
  }

  @Test
  void document_generation_never_creates_missing_signers() throws Exception {
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
  void missing_configuration_returns_nonzero_exit_codes() {
    assertThat(cli(name -> null).execute("pid-issuer", "generate", "-c", "missing.yaml"))
        .isEqualTo(1);

    assertThat(err.toString()).contains("Configuration file not found");
  }

  private static Stream<Arguments> participants() {
    return Stream.of(
        Arguments.of("pidIssuer", "pid-issuer", "PID_ISSUER_KEYSTORE_PASSWORD",
            "certificates/issuer/pid_issuer.p12", "pid_issuer"),
        Arguments.of("walletAttestationIssuer", "wallet-attestation-issuer",
            "WALLET_ATTESTATION_ISSUER_KEYSTORE_PASSWORD",
            "certificates/wallet-attestation-issuer/wallet_attestation_issuer.p12",
            "wallet_attestation_issuer"),
        Arguments.of("verifier.access", "verifier access",
            "VERIFIER_ACCESS_CERTIFICATE_KEYSTORE_PASSWORD",
            "certificates/verifier-access-certificate/verifier-access-certificate.p12",
            "verifier_access_certificate"),
        Arguments.of("verifier.registration", "verifier registration",
            "VERIFIER_REGISTRATION_CERTIFICATE_KEYSTORE_PASSWORD",
            "certificates/verifier-registration-certificate/verifier-registration-certificate.p12",
            "registration"));
  }

  private WalletPkiCli cli(Function<String, String> passwords) {
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
    selected.remove(List.of("pidIssuer", "walletAttestationIssuer", "verifier", "trustSource"));
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
    Path file = directory.resolve("selected.yaml");
    Files.writeString(file, yaml.writeValueAsString(selected));
    return file;
  }

  private void deleteAuthorityPrivateKeys(boolean includeSigner) throws Exception {
    for (var role : AuthorityRole.values()) {
      if (includeSigner || role != AuthorityRole.TRUST_SOURCE) {
        Files.delete(directory.resolve("state/ca").resolve(role.directory())
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

  private JsonNode loteEntries() throws Exception {
    var token = JWSObject.parse(Files.readString(
        directory.resolve("config/trust-source/signed/trusted-entities.json")));
    return yaml.readTree(token.getPayload().toString()).at("/LoTE/TrustedEntitiesList");
  }
}
