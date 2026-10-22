// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import java.io.File;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import se.digg.wallet.pki.application.EcosystemProvisioner;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;

/** The only CLI operation that can create managed root authorities. */
@Command(name = "init-authorities", mixinStandardHelpOptions = true,
    description = "Initialize managed authorities, validate existing roots and publish their certificates/CRLs. Never replaces an existing root.")
public class InitAuthoritiesCommand implements Callable<Integer> {
  @Spec
  private CommandSpec spec;
  @Option(names = {"-c", "--config"}, required = true,
      description = "Role-based ecosystem YAML configuration.")
  private File configFile;
  private final ConfigurationLoader loader;
  private final EcosystemProvisioner provisioner;

  public InitAuthoritiesCommand() {
    this(new ConfigurationLoader(), new SecretResolver());
  }

  public InitAuthoritiesCommand(ConfigurationLoader loader, SecretResolver secrets) {
    this.loader = loader;
    this.provisioner = new EcosystemProvisioner(secrets);
  }

  @Override
  public Integer call() {
    try {
      provisioner.initializeAuthorities(loader.load(configFile.toPath()),
          spec.commandLine().getOut());
      return 0;
    } catch (Exception e) {
      spec.commandLine().getErr().println("Error: " + e.getMessage());
      return 1;
    }
  }
}
