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
  void malformed_wallet_configuration_is_rejected(String before, String after) throws Exception {
    Path source = TestEnvironment.create(directory);
    Files.writeString(source, Files.readString(source).replace(before, after));

    assertThatThrownBy(() -> new ConfigurationLoader().load(source))
        .isInstanceOf(PkiConfigurationException.class);

    assertThat(directory.resolve("authorities")).doesNotExist();
  }

  @Test
  void paths_are_relative_to_the_configuration_file() throws Exception {
    var source = TestEnvironment.create(directory);

    var config = new ConfigurationLoader().load(source);

    assertThat(config.authorityDirectory()).isEqualTo(directory.resolve("authorities").toString());
    assertThat(config.pidIssuer().keystorePassword().file())
        .isEqualTo(directory.resolve("password.txt").toString());
  }

  @Test
  void country_codes_are_never_interpreted_as_yaml_booleans() throws Exception {
    var source = TestEnvironment.create(directory);
    Files.writeString(source, Files.readString(source).replace("country: SE", "country: NO"));

    var config = new ConfigurationLoader().load(source);

    assertThat(config.organization().country()).isEqualTo("NO");
  }

  private static Stream<Arguments> invalidConfigurations() {
    return Stream.of(
        Arguments.of("publicationBaseUrl: http://trust-source",
            "publicationBaseUrl: http://trust-source\nstateDirectory: legacy"),
        Arguments.of("publicationBaseUrl: http://trust-source",
            "publicationBaseUrl: http://trust-source\npublicationBaseUrl: http://duplicate"),
        Arguments.of("authorityDirectory: authorities", "authorityDirectory: generated/private"),
        Arguments.of("source: managed", "source: unknown"),
        Arguments.of("source: managed", "source: managed\n    profile: service"),
        Arguments.of("source: managed", "source: existing"),
        Arguments.of("country: SE", "country: Sweden"),
        Arguments.of("file: password.txt", "file: password.txt\n    env: SECRET"),
        Arguments.of("sequenceNumber: 1", "sequenceNumber: 0"),
        Arguments.of("publicBaseUrl: https://localhost/local-registration-certificate",
            "publicBaseUrl: relative"),
        Arguments.of("dns: [localhost, pid-issuer]", "ip: [not-an-address]"));
  }
}
