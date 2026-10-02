// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;
import org.junit.jupiter.api.Test;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;

class WalletPkiCliTest {

  @Test
  void shouldDisplayHelp() {
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();
    WalletPkiCli cli = new WalletPkiCli(new PrintWriter(out), new PrintWriter(err));

    int exitCode = cli.execute("--help");

    assertThat(exitCode).isEqualTo(0);
    assertThat(out.toString()).contains("wallet-pki", "generate", "Commands:");
  }

  @Test
  void shouldDisplayVersion() {
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();
    WalletPkiCli cli = new WalletPkiCli(new PrintWriter(out), new PrintWriter(err));

    int exitCode = cli.execute("--version");

    assertThat(exitCode).isEqualTo(0);
    assertThat(out.toString()).contains("wallet-pki 0.1.0");
  }

  @Test
  void shouldExecuteGenerateWithValidConfigAndSecrets() {
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();

    Map<String, String> mockEnv =
        Map.of(
            "TEST_VERIFIER_KEYSTORE_PASSWORD", "secret1",
            "TEST_PID_ISSUER_KEYSTORE_PASSWORD", "secret2",
            "TEST_PROVIDER_KEYSTORE_PASSWORD", "secret3");

    WalletPkiCli cli =
        new WalletPkiCli(
            new ConfigurationLoader(),
            new SecretResolver(mockEnv::get),
            new PrintWriter(out),
            new PrintWriter(err));

    int exitCode = cli.execute("generate", "--config", "src/test/resources/test-ecosystem.yaml");

    assertThat(exitCode).isEqualTo(0);
    assertThat(out.toString())
        .contains("Environment: local")
        .contains("Output Directory: ./target/test-certificates")
        .contains("Authorities: 4 configured")
        .contains("Certificates: 3 configured")
        .contains("Trust lists: 1 configured")
        .contains("Configuration validated successfully.");
  }

  @Test
  void shouldExecuteGenerateWithSelectiveTargets() {
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();

    Map<String, String> mockEnv = Map.of("TEST_VERIFIER_KEYSTORE_PASSWORD", "secret1");

    WalletPkiCli cli =
        new WalletPkiCli(
            new ConfigurationLoader(),
            new SecretResolver(mockEnv::get),
            new PrintWriter(out),
            new PrintWriter(err));

    int exitCode =
        cli.execute(
            "generate",
            "--config",
            "src/test/resources/test-ecosystem.yaml",
            "verifier-access-certificate");

    assertThat(exitCode).isEqualTo(0);
    assertThat(out.toString())
        .contains("Selected targets for generation: verifier-access-certificate")
        .contains("Secret for certificate 'verifier-access-certificate' resolved successfully");
  }

  @Test
  void shouldFailGenerateWhenConfigNotFound() {
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();

    WalletPkiCli cli = new WalletPkiCli(new PrintWriter(out), new PrintWriter(err));
    int exitCode = cli.execute("generate", "--config", "non-existent-config.yaml");

    assertThat(exitCode).isNotEqualTo(0);
    assertThat(err.toString()).contains("Configuration file not found");
  }

  @Test
  void shouldFailGenerateWhenSecretIsMissing() {
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();

    WalletPkiCli cli =
        new WalletPkiCli(
            new ConfigurationLoader(),
            new SecretResolver(key -> null),
            new PrintWriter(out),
            new PrintWriter(err));

    int exitCode = cli.execute("generate", "--config", "src/test/resources/test-ecosystem.yaml");

    assertThat(exitCode).isEqualTo(1);
    assertThat(err.toString()).contains("is not set or empty");
  }
}
