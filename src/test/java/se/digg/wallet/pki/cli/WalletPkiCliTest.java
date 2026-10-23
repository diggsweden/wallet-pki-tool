// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import static org.assertj.core.api.Assertions.assertThat;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.support.EcosystemFixture;

class WalletPkiCliTest {
  @TempDir
  Path directory;
  private final StringWriter out = new StringWriter();
  private final StringWriter err = new StringWriter();

  @Test
  void help_lists_authority_initialization_and_generation() {
    assertThat(cli().execute("--help")).isZero();
    assertThat(out.toString()).contains("init-authorities", "generate");
  }

  @Test
  void authority_initialization_does_not_require_keystore_passwords() throws Exception {
    var cli = new WalletPkiCli(new ConfigurationLoader(), new SecretResolver(name -> null),
        new PrintWriter(out), new PrintWriter(err));
    assertThat(cli.execute("init-authorities", "-c",
        EcosystemFixture.configurationFile(directory).toString())).isZero();
    assertThat(out.toString()).contains("Authority ready: pid-issuer",
        "Authority ready: trust-source");
    assertThat(err.toString()).isEmpty();
  }

  @Test
  void initialized_pid_issuer_can_be_generated_through_the_cli() throws Exception {
    Path file = EcosystemFixture.configurationFile(directory);
    var cli = cli();
    assertThat(cli.execute("init-authorities", "-c", file.toString())).isZero();
    assertThat(cli.execute("generate", "-c", file.toString(), "pid-issuer")).isZero();
    assertThat(out.toString()).contains("Generated: pid-issuer", "Generation completed");
    assertThat(err.toString()).isEmpty();
  }

  @Test
  void unknown_targets_and_missing_configuration_have_nonzero_exit_codes() throws Exception {
    assertThat(cli().execute("generate", "-c",
        EcosystemFixture.configurationFile(directory).toString(), "typo")).isEqualTo(1);
    assertThat(err.toString()).contains("Unknown generation target");
    assertThat(cli().execute("generate", "-c", "missing.yaml")).isEqualTo(1);
    assertThat(err.toString()).contains("Configuration file not found");
  }

  @Test
  void generation_without_initialization_reports_the_required_command() throws Exception {
    assertThat(cli().execute("generate", "-c",
        EcosystemFixture.configurationFile(directory).toString(), "pid-issuer")).isEqualTo(1);
    assertThat(err.toString()).contains("init-authorities");
  }

  private WalletPkiCli cli() {
    return new WalletPkiCli(new ConfigurationLoader(), new SecretResolver(name -> "test-password"),
        new PrintWriter(out), new PrintWriter(err));
  }
}
