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

class ConfigurationLoaderTest {
  @TempDir
  Path directory;
  private final ConfigurationLoader loader = new ConfigurationLoader();

  @Test
  void the_example_declares_all_five_authorities_and_their_consumers() throws Exception {
    var config = loader.load(EcosystemFixture.configurationFile(directory));
    assertThat(config.pidIssuer().authority().source()).isEqualTo(AuthorityConfig.Source.MANAGED);
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

  @Test
  void managed_and_existing_authority_settings_cannot_be_mixed() {
    assertThatThrownBy(
        () -> new AuthorityConfig(AuthorityConfig.Source.MANAGED, "CA", "cert", "key", "crl"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
        () -> new AuthorityConfig(AuthorityConfig.Source.EXISTING, null, "cert", "key", null))
        .hasMessageContaining("crlFile");
  }

  @Test
  void duplicate_yaml_fields_are_rejected() throws Exception {
    assertInvalid(EcosystemFixture.yaml(directory).replace("schemaVersion: 1", "schemaVersion: 1\n schemaVersion: 1".replace("\n ", "\n")), "Duplicate field");
  }

  private void assertInvalid(String yaml, String message) throws Exception {
    Path file = directory.resolve("invalid.yaml");
    Files.writeString(file, yaml);
    assertThatThrownBy(() -> loader.load(file)).isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining(message);
  }
}
