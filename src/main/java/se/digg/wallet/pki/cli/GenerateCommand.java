// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import se.digg.wallet.pki.config.CertificateConfig;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;

/** Subcommand for generating PKI certificates, keystores, and trust lists. */
@Command(
    name = "generate",
    mixinStandardHelpOptions = true,
    description = "Generate certificates, keystores, and LoTE from a YAML configuration.")
public class GenerateCommand implements Callable<Integer> {

  @Spec
  private CommandSpec spec;

  @Option(
      names = {"-c", "--config"},
      required = true,
      description = "Path to the YAML configuration file.")
  private File configFile;

  @Parameters(
      paramLabel = "TARGETS",
      description = {
          "Optional specific target IDs (authorities, certificates,",
          "or trust lists) to generate."
      })
  private List<String> targets = new ArrayList<>();

  private final ConfigurationLoader configLoader;
  private final SecretResolver secretResolver;

  /** Default constructor. */
  public GenerateCommand() {
    this(new ConfigurationLoader(), new SecretResolver());
  }

  /**
   * Constructor with explicit dependencies (useful for testing).
   *
   * @param configLoader the configuration loader
   * @param secretResolver the secret resolver
   */
  public GenerateCommand(ConfigurationLoader configLoader, SecretResolver secretResolver) {
    this.configLoader = configLoader;
    this.secretResolver = secretResolver;
  }

  @Override
  public Integer call() {
    PrintWriter out =
        spec != null
            ? spec.commandLine().getOut()
            : new PrintWriter(System.out, true, StandardCharsets.UTF_8);
    PrintWriter err =
        spec != null
            ? spec.commandLine().getErr()
            : new PrintWriter(System.err, true, StandardCharsets.UTF_8);

    try {
      out.printf("Loading configuration from: %s%n", configFile.getPath());
      PkiConfiguration config = configLoader.load(configFile.toPath());

      out.printf(
          "Environment: %s%n",
          config.getEnvironment() != null ? config.getEnvironment() : "default");
      out.printf("Output Directory: %s%n", config.getOutputDir());
      out.printf("Authorities: %d configured%n", config.getAuthorities().size());
      out.printf("Certificates: %d configured%n", config.getCertificates().size());
      out.printf("Trust lists: %d configured%n", config.getTrustLists().size());

      if (targets != null && !targets.isEmpty()) {
        out.printf("Selected targets for generation: %s%n", String.join(", ", targets));
      } else {
        out.println("Generating all configured authorities, certificates, and trust lists...");
      }

      // Validate that secrets can be resolved safely
      for (CertificateConfig cert : config.getCertificates()) {
        if (targets == null || targets.isEmpty() || targets.contains(cert.getId())) {
          // Verify password resolution without printing the secret value
          secretResolver.resolveKeystorePassword(cert);
          out.printf("  ✓ Secret for certificate '%s' resolved successfully%n", cert.getId());
        }
      }

      out.println("Configuration validated successfully.");
      return 0;
    } catch (Exception e) {
      err.printf("Error: %s%n", e.getMessage());
      return 1;
    }
  }

  public File getConfigFile() {
    return configFile;
  }

  public void setConfigFile(File configFile) {
    this.configFile = configFile;
  }

  public List<String> getTargets() {
    return new ArrayList<>(targets);
  }

  public void setTargets(List<String> targets) {
    this.targets = targets != null ? new ArrayList<>(targets) : new ArrayList<>();
  }
}
