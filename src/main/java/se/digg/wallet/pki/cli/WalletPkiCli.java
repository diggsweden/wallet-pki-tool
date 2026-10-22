// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import java.io.PrintWriter;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;

/** Composition root for the wallet ecosystem CLI. */
@Command(name = "wallet-pki", mixinStandardHelpOptions = true, version = "wallet-pki 0.1.0",
    description = "Certificate and trust-document provisioning for the Digg wallet ecosystem.",
    subcommands = CommandLine.HelpCommand.class)
public class WalletPkiCli {
  private final CommandLine commandLine;

  public WalletPkiCli() {
    this(new ConfigurationLoader(), new SecretResolver(), null, null);
  }

  public WalletPkiCli(PrintWriter out, PrintWriter err) {
    this(new ConfigurationLoader(), new SecretResolver(), out, err);
  }

  public WalletPkiCli(ConfigurationLoader loader, SecretResolver secrets, PrintWriter out,
      PrintWriter err) {
    commandLine = new CommandLine(this)
        .addSubcommand(new GenerateCommand(loader, secrets))
        .addSubcommand(new InitAuthoritiesCommand(loader, secrets));
    if (out != null)
      commandLine.setOut(out);
    if (err != null)
      commandLine.setErr(err);
  }

  public static void main(String[] args) {
    System.exit(new WalletPkiCli().execute(args));
  }

  public int execute(String... args) {
    return commandLine.execute(args);
  }
}
