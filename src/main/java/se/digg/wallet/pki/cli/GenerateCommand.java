// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import se.digg.wallet.pki.application.EcosystemProvisioner;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;

/** Provisions named roles using already initialized authorities. */
@Command(name = "generate", mixinStandardHelpOptions = true,
    description = "Generate wallet ecosystem artifacts using initialized authorities.")
public class GenerateCommand implements Callable<Integer> {
  @Spec
  private CommandSpec spec;
  @Option(names = {"-c", "--config"}, required = true,
      description = "Role-based ecosystem YAML configuration.")
  private File configFile;
  @Parameters(paramLabel = "TARGETS",
      description = "Optional targets: pid-issuer, wallet-provider, verifier-access, verifier-registration, trust-source, lote, status-list. Default: all.")
  private List<String> targets = new ArrayList<>();
  private final ConfigurationLoader loader;
  private final EcosystemProvisioner provisioner;

  public GenerateCommand() {
    this(new ConfigurationLoader(), new SecretResolver());
  }

  public GenerateCommand(ConfigurationLoader loader, SecretResolver secrets) {
    this.loader = loader;
    this.provisioner = new EcosystemProvisioner(secrets);
  }

  @Override
  public Integer call() {
    try {
      var config = loader.load(configFile.toPath());
      provisioner.generate(config, targets, spec.commandLine().getOut());
      spec.commandLine().getOut().println("Generation completed: " + config.outputDirectory());
      return 0;
    } catch (Exception e) {
      spec.commandLine().getErr().println("Error: " + e.getMessage());
      return 1;
    }
  }
}
