// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;

class WalletPkiCliTest {

  @Test
  void shouldDisplayHelp() {
    // 1. Execute CLI with --help flag
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();
    WalletPkiCli cli = new WalletPkiCli(new PrintWriter(out), new PrintWriter(err));

    int exitCode = cli.execute("--help");

    // 2. Verify command description and available subcommands
    assertThat(exitCode).isEqualTo(0);
    assertThat(out.toString()).contains("wallet-pki", "generate", "Commands:");
  }

  @Test
  void shouldDisplayVersion() {
    // 1. Execute CLI with --version flag
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();
    WalletPkiCli cli = new WalletPkiCli(new PrintWriter(out), new PrintWriter(err));

    int exitCode = cli.execute("--version");

    // 2. Verify version string output
    assertThat(exitCode).isEqualTo(0);
    assertThat(out.toString()).contains("wallet-pki 0.1.0");
  }

  @Test
  void shouldExecuteGenerateWithValidConfigAndSecrets(@TempDir Path tempDir) throws Exception {
    // 1. Mock required environment variables for all certificates
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

    Path configPath = createIsolatedConfigFile(tempDir);

    // 2. Execute generate command
    int exitCode = cli.execute("generate", "--config", configPath.toString());

    // 3. Verify resource counts and successful validation
    assertThat(exitCode).isEqualTo(0);
    assertThat(out.toString())
        .contains("Environment: local")
        .contains("Output Directory: " + tempDir)
        .contains("Authorities: 4 configured")
        .contains("Certificates: 3 configured")
        .contains("Trust lists: 1 configured")
        .contains("Generation completed successfully.");
  }

  @Test
  void shouldExecuteGenerateWithSelectiveTargets(@TempDir Path tempDir) throws Exception {
    // 1. Mock secret only for the targeted certificate
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();

    Map<String, String> mockEnv = Map.of("TEST_VERIFIER_KEYSTORE_PASSWORD", "secret1");

    WalletPkiCli cli =
        new WalletPkiCli(
            new ConfigurationLoader(),
            new SecretResolver(mockEnv::get),
            new PrintWriter(out),
            new PrintWriter(err));

    Path configPath = createIsolatedConfigFile(tempDir);

    // 2. Execute generate command with selective target
    int exitCode =
        cli.execute(
            "generate",
            "--config",
            configPath.toString(),
            "verifier-access-certificate");

    // 3. Verify only targeted certificate secret was resolved
    assertThat(exitCode).isEqualTo(0);
    assertThat(out.toString())
        .contains("Selected targets for generation: verifier-access-certificate")
        .contains("Secret for certificate 'verifier-access-certificate' resolved successfully");
  }

  @Test
  void shouldFailGenerateWhenConfigNotFound() {
    // Verify non-zero exit code when configuration file is not found
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();

    WalletPkiCli cli = new WalletPkiCli(new PrintWriter(out), new PrintWriter(err));
    int exitCode = cli.execute("generate", "--config", "non-existent-config.yaml");

    assertThat(exitCode).isNotEqualTo(0);
    assertThat(err.toString()).contains("Configuration file not found");
  }

  @Test
  void shouldFailGenerateWhenSecretIsMissing(@TempDir Path tempDir) throws Exception {
    // Verify non-zero exit code when required secret environment variable is missing
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();

    WalletPkiCli cli =
        new WalletPkiCli(
            new ConfigurationLoader(),
            new SecretResolver(key -> null),
            new PrintWriter(out),
            new PrintWriter(err));

    Path configPath = createIsolatedConfigFile(tempDir);

    int exitCode = cli.execute("generate", "--config", configPath.toString());

    assertThat(exitCode).isEqualTo(1);
    assertThat(err.toString()).contains("is not set or empty");
  }

  private Path createIsolatedConfigFile(Path tempDir) throws Exception {
    String originalYaml =
        Files.readString(
            Path.of("src/test/resources/test-ecosystem.yaml"), StandardCharsets.UTF_8);
    String customizedYaml =
        originalYaml.replace(
            "outputDir: ./target/test-certificates", "outputDir: " + tempDir.toString());
    Path configPath = tempDir.resolve("test-ecosystem.yaml");
    Files.writeString(configPath, customizedYaml, StandardCharsets.UTF_8);
    return configPath;
  }
}
