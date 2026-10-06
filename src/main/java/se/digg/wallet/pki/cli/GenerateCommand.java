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
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.crypto.KeystoreManager;
import se.digg.wallet.pki.generator.PkiEngine;

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
  private final PkiEngine pkiEngine;

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
    this(
        configLoader,
        secretResolver,
        new PkiEngine(
            new EcKeyGenerator(),
            new CertificateAuthorityManager(),
            new CertificateProfileIssuer(),
            new KeystoreManager(),
            secretResolver));
  }

  /**
   * Full constructor with explicit dependencies.
   *
   * @param configLoader the configuration loader
   * @param secretResolver the secret resolver
   * @param pkiEngine the PKI generator engine
   */
  public GenerateCommand(
      ConfigurationLoader configLoader, SecretResolver secretResolver, PkiEngine pkiEngine) {
    this.configLoader = configLoader;
    this.secretResolver = secretResolver;
    this.pkiEngine = pkiEngine;
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
      // 1. Load and parse YAML configuration
      out.println("Loading configuration from: %s".formatted(configFile.getPath()));
      PkiConfiguration config = configLoader.load(configFile.toPath());

      out.println(
          "Environment: %s"
              .formatted(config.environment() != null ? config.environment() : "default"));
      out.println("Output Directory: %s".formatted(config.outputDir()));
      out.println("Authorities: %d configured".formatted(config.authorities().size()));
      out.println("Certificates: %d configured".formatted(config.certificates().size()));
      out.println("Trust lists: %d configured".formatted(config.trustLists().size()));

      if (targets != null && !targets.isEmpty()) {
        out.println("Selected targets for generation: %s".formatted(String.join(", ", targets)));
      } else {
        out.println("Generating all configured authorities, certificates, and trust lists...");
      }

      // 2. Validate that secrets can be resolved safely for selected targets
      for (CertificateConfig cert : config.certificates()) {
        if (targets == null || targets.isEmpty() || targets.contains(cert.id())) {
          secretResolver.resolveKeystorePassword(cert);
          out.println("  ✓ Secret for certificate '%s' resolved successfully".formatted(cert.id()));
        }
      }

      // 3. Execute CA, certificate, and keystore generation
      pkiEngine.generate(config, targets, out);

      out.println("Generation completed successfully.");
      return 0;
    } catch (Exception e) {
      err.println("Error: %s".formatted(e.getMessage()));
      return 1;
    }
  }
}
