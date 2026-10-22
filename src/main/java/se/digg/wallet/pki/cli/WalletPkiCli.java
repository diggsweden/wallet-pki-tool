// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import se.digg.wallet.pki.application.Operation;
import se.digg.wallet.pki.application.ProvisioningReport;
import se.digg.wallet.pki.application.WalletProvisioner;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.storage.ArtifactStore;

/** Wallet-role operations using the explicitly configured authority sources. */
@Command(name = "wallet-pki", mixinStandardHelpOptions = true, version = "wallet-pki 0.1.0",
    description = "Maintain certificates and signed documents for wallet participants.")
public final class WalletPkiCli {
  private final CommandLine commandLine;

  public WalletPkiCli() {
    this(new SecretResolver(), Clock.systemUTC(), null, null);
  }

  public WalletPkiCli(PrintWriter out, PrintWriter err) {
    this(new SecretResolver(), Clock.systemUTC(), out, err);
  }

  public WalletPkiCli(SecretResolver secrets, Clock clock, PrintWriter out, PrintWriter err) {
    commandLine = new CommandLine(this);
    for (Operation operation : Operation.values()) {
      commandLine.addSubcommand(operation.name().toLowerCase(java.util.Locale.ROOT),
          new RoleCommand(operation, new WalletProvisioner(secrets, clock)));
    }
    commandLine.addSubcommand("help", new CommandLine.HelpCommand());
    if (out != null) {
      commandLine.setOut(out);
    }
    if (err != null) {
      commandLine.setErr(err);
    }
  }

  public static void main(String[] args) {
    System.exit(new WalletPkiCli().execute(args));
  }

  public int execute(String... args) {
    return commandLine.execute(args);
  }

  @Command(mixinStandardHelpOptions = true,
      description = "Ensure, renew, rotate or verify the selected wallet roles.")
  private static final class RoleCommand implements Callable<Integer> {
    @Spec
    private CommandSpec spec;
    @Option(names = {"-c", "--config"}, required = true,
        description = "Typed wallet environment YAML.")
    private Path configuration;
    @Option(names = "--json",
        description = "Print the immutable bundle path and role operations as JSON.")
    private boolean json;
    @Parameters(paramLabel = "ROLES",
        description = "pid-issuer, wallet-provider, verifier-access, "
            + "verifier-registration, trust-source. "
            + "Defaults to configured roles for ensure/verify.")
    private List<String> roles = new ArrayList<>();
    private final Operation operation;
    private final WalletProvisioner provisioner;

    RoleCommand(Operation operation, WalletProvisioner provisioner) {
      this.operation = operation;
      this.provisioner = provisioner;
    }

    @Override
    public Integer call() {
      try {
        ProvisioningReport report = provisioner.run(configuration, operation, roles);
        if (json) {
          spec.commandLine().getOut().println(ArtifactStore.JSON.writeValueAsString(Map.of(
              "environment", report.environment(), "generation", report.generation(),
              "bundle", report.bundle().toString(), "roles", report.roles())));
        } else {
          report.roles().forEach((role, action) -> spec.commandLine().getOut()
              .println(action + " " + role.argument()));
          spec.commandLine().getOut().println("Bundle: " + report.bundle());
        }
        return 0;
      } catch (Exception e) {
        spec.commandLine().getErr().println("Error: " + e.getMessage());
        return 1;
      }
    }
  }
}
