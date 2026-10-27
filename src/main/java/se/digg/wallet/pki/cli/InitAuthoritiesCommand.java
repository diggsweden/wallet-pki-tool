// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.Supplier;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import se.digg.wallet.pki.application.AuthorityProvisioner;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.domain.AuthorityRole;

/** The only CLI operation that can create managed root authorities. */
@Command(name = "init", mixinStandardHelpOptions = true,
    description = "Create missing authorities and publish their certificates/CRLs. "
        + "Reuse existing roots; never replace incomplete roots. "
        + "Requires shared organization/caDistribution settings "
        + "and selected authority common names; "
        + "no keystore passwords required.")
final class InitAuthoritiesCommand implements Callable<Integer> {
  @Spec
  private CommandSpec spec;
  @Parameters(paramLabel = "ROLES",
      description = "Optional authorities: pid-issuer, wallet-attestation-issuer, "
          + "verifier-access, verifier-registration, trust-source. Default: all five.")
  private List<AuthorityRole> roles = new ArrayList<>();
  private final ConfigurationLoader loader;
  private final Supplier<Path> configuration;

  InitAuthoritiesCommand(ConfigurationLoader loader, Supplier<Path> configuration) {
    this.loader = loader;
    this.configuration = configuration;
  }

  @Override
  public Integer call() {
    try {
      new AuthorityProvisioner().initialize(loader.load(configuration.get()),
          roles.isEmpty() ? EnumSet.allOf(AuthorityRole.class) : EnumSet.copyOf(roles),
          spec.commandLine().getOut());
      return 0;
    } catch (Exception e) {
      spec.commandLine().getErr().println("Error: " + e.getMessage());
      return 1;
    }
  }
}
