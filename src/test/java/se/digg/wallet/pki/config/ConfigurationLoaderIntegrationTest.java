// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import se.digg.wallet.pki.TestEnvironment;

class ConfigurationLoaderIntegrationTest {
  @TempDir
  Path directory;

  @ParameterizedTest
  @MethodSource("invalidConfigurations")
  void invalid_configuration_is_rejected_before_state_is_created(String before, String after)
      throws Exception {
    Path source = TestEnvironment.create(directory);
    Files.writeString(source, Files.readString(source).replace(before, after));

    assertThatThrownBy(() -> new ConfigurationLoader().load(source))
        .isInstanceOf(PkiConfigurationException.class);

    assertThat(directory.resolve("state")).doesNotExist();
    assertThat(directory.resolve("bundles")).doesNotExist();
  }

  @Test
  void paths_are_relative_to_the_configuration_file() throws Exception {
    Path source = TestEnvironment.create(directory);

    var config = new ConfigurationLoader().load(source);

    assertThat(config.stateDir()).isEqualTo(directory.resolve("state").toString());
    assertThat(config.identities().getFirst().passwordFile())
        .isEqualTo(directory.resolve("password.txt").toString());
  }

  @Test
  void stage_configuration_uses_only_imported_authorities() {
    var config = new ConfigurationLoader().load(Path.of("examples/stage.yaml"));

    assertThat(config.authorities()).allSatisfy(authority -> {
      assertThat(authority.create()).isFalse();
      assertThat(authority.keyFile()).startsWith("/run/secrets/");
      assertThat(authority.certFile()).startsWith("/run/secrets/");
    });
  }

  private static Stream<Arguments> invalidConfigurations() {
    return Stream.of(
        Arguments.of("schemaVersion: 1", "schemaVersion: 2"),
        Arguments.of("schemaVersion: 1", "schemaVersion: 1\nunrecognized: true"),
        Arguments.of("environment: local", "environment: local\nenvironment: local"),
        Arguments.of("stateDir: state", "stateDir: bundles/private"),
        Arguments.of("profile: pid-issuer-service", "profile: unknown-profile"),
        Arguments.of("profile: trust-source-signer", "profile: encryption"),
        Arguments.of("profile: pid-issuer-service", "profile: pid-issuer-service\n    typo: true"),
        Arguments.of("alias: pid_issuer", "alias: nonce-encryption"),
        Arguments.of("alias: pid_issuer", "alias: PID_ISSUER"),
        Arguments.of("id: wallet-provider", "id: pid-issuer"),
        Arguments.of("signer: trust-list-signer", "signer: unknown"),
        Arguments.of("role: wallet", "role: guessed"),
        Arguments.of("reference: authority:pid-issuer", "reference: pid-issuer"),
        Arguments.of("format: pkcs12", "format: unsupported"),
        Arguments.of("private/certificates/issuer/pid_issuer.p12", "../pid_issuer.p12"),
        Arguments.of("private/certificates/issuer/pid_issuer.p12", "public/pid_issuer.p12"),
        Arguments.of("public/trust-source/signed/status-list.jwt",
            "public/trust-source/signed/trusted-entities.json"),
        Arguments.of("variable: VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE",
            "variable: invalid-name"));
  }
}
