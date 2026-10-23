// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import se.digg.wallet.pki.support.EcosystemFixture;
import tools.jackson.databind.node.ObjectNode;
import tools.jackson.dataformat.yaml.YAMLMapper;

class ConfigurationLoaderTest {
  @TempDir
  Path directory;
  private final ConfigurationLoader loader = new ConfigurationLoader();

  @Test
  void the_example_configures_participants_without_authority_settings() throws Exception {
    var config = loader.load(EcosystemFixture.configurationFile(directory));
    assertThat(config.pidIssuer().signing().commonName()).isEqualTo("PID Issuer (Ecosystem)");
    assertThat(config.walletProvider().signing().subjectAlternativeNames().dns())
        .contains("wallet-provider");
    assertThat(config.verifier().registration().registration().requestedPidClaims())
        .contains("address.street_address");
    assertThat(config.trustSource().signer().keystorePassword().env())
        .isEqualTo("TRUST_SOURCE_KEYSTORE_PASSWORD");
  }

  @ParameterizedTest
  @ValueSource(strings = {"unknownSetting: true\n", "authorities: []\n", "certificates: []\n",
      "trustLists: []\n"})
  void unknown_and_legacy_root_fields_are_rejected(String extra) throws Exception {
    assertInvalid(EcosystemFixture.yaml(directory) + extra, "Unrecognized property");
  }

  @Test
  void misspelled_nested_fields_are_rejected() throws Exception {
    assertInvalid(EcosystemFixture.yaml(directory).replace("    commonName: PID Issuer (Ecosystem)",
        "    commonName: PID Issuer (Ecosystem)\n    signign: true"), "signign");
  }

  @Test
  void unsupported_schema_versions_are_rejected() throws Exception {
    assertInvalid(EcosystemFixture.yaml(directory).replace("schemaVersion: 1", "schemaVersion: 2"),
        "schemaVersion must be 1");
  }

  @Test
  void ambiguous_password_sources_are_rejected() throws Exception {
    assertInvalid(EcosystemFixture.yaml(directory).replace("env: PID_ISSUER_KEYSTORE_PASSWORD",
        "env: PID_ISSUER_KEYSTORE_PASSWORD\n    file: password.txt"), "exactly one");
  }

  @Test
  void private_state_cannot_be_published_as_trust_source_content() throws Exception {
    assertInvalid(EcosystemFixture.yaml(directory).replace(directory.resolve("state").toString(),
        directory.resolve("config/trust-source/private").toString()), "must not overlap");
  }

  @Test
  void missing_required_role_sections_are_rejected() throws Exception {
    assertInvalid("schemaVersion: 1\nstateDirectory: state\noutputDirectory: config\n",
        "organization is required");
  }

  @Test
  void empty_configuration_is_rejected() throws Exception {
    assertInvalid("", "Invalid configuration");
  }

  @Test
  void missing_configuration_is_rejected() {
    assertThatThrownBy(() -> loader.load(directory.resolve("missing.yaml")))
        .hasMessageContaining("Configuration file not found");
  }

  @ParameterizedTest
  @ValueSource(strings = {"pidIssuer", "walletProvider", "verifier.access", "verifier.registration",
      "trustSource"})
  void authority_settings_are_rejected_for_every_role(String section) throws Exception {
    var yaml = YAMLMapper.builder().build();
    var document = yaml.readTree(EcosystemFixture.yaml(directory));
    var participant = document;
    for (String component : section.split("\\.")) {
      participant = participant.path(component);
    }
    ((ObjectNode) participant).putObject("authority").put("source", "managed");
    assertInvalid(yaml.writeValueAsString(document), "authority");
  }

  @ParameterizedTest
  @ValueSource(strings = {"../outside.p12", "/absolute.p12", "."})
  void artifact_paths_must_be_relative_to_the_output_directory(String path) throws Exception {
    assertInvalid(EcosystemFixture.yaml(directory)
        .replace("keystoreFile: certificates/issuer/pid_issuer.p12", "keystoreFile: " + path),
        "relative path");
  }

  @Test
  void duplicate_yaml_fields_are_rejected() throws Exception {
    Path file = directory.resolve("duplicate.yaml");
    Files.writeString(file, EcosystemFixture.yaml(directory)
        .replace("schemaVersion: 1", "schemaVersion: 1\nschemaVersion: 1"));
    assertThatThrownBy(() -> loader.load(file)).isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("Duplicate")
        .hasMessageContaining("schemaVersion");
  }

  @Test
  void the_single_participant_example_has_no_unrelated_role_requirements() {
    var config = loader.load(Path.of("examples/wallet-provider.yaml"));

    assertThat(config.walletProvider().keystoreFile())
        .isEqualTo("certificates/wallet-provider/wallet_provider.p12");
    assertThat(config.publication().baseUrl()).isEqualTo("http://trust-source");
    assertThat(config.pidIssuer()).isNull();
    assertThat(config.verifier()).isNull();
    assertThat(config.trustSource()).isNull();
  }

  @Test
  void legacy_publication_settings_resolve_to_the_shared_publication_contract() throws Exception {
    var config = loader.load(EcosystemFixture.configurationFile(directory));

    assertThat(config.publication())
        .isEqualTo(new PublicationConfig("http://trust-source", "trust-source",
            "trust-source/revocation-list.pem"));
  }

  @Test
  void mixed_publication_locations_are_rejected() throws Exception {
    assertInvalid(EcosystemFixture.yaml(directory) + """
        publication:
          baseUrl: http://another-trust-source
          directory: public
          rootCrlFile: public/revocation-list.pem
        """, "not both");
  }

  @Test
  void shared_publication_settings_preserve_private_state_separation() throws Exception {
    String config = Files.readString(Path.of("examples/wallet-provider.yaml"))
        .replace("stateDirectory: ./.wallet-pki", "stateDirectory: ./config/trust-source/private");

    assertInvalid(config, "must not overlap");
  }

  private void assertInvalid(String yaml, String message) throws Exception {
    Path file = directory.resolve("invalid.yaml");
    Files.writeString(file, yaml);
    assertThatThrownBy(() -> loader.load(file)).isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining(message);
  }
}
