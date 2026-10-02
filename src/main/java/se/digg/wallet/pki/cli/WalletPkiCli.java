// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import java.io.PrintWriter;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.IFactory;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;

/** Main command-line interface entry point for wallet-pki-tool. */
@Command(
    name = "wallet-pki",
    mixinStandardHelpOptions = true,
    version = "wallet-pki 0.1.0",
    description = "PKI, certificate and trust list automation tool for the Digg wallet-ecosystem.",
    subcommands = {GenerateCommand.class, CommandLine.HelpCommand.class})
public class WalletPkiCli {

  private final CommandLine commandLine;

  /** Default constructor initializing the Picocli command line. */
  public WalletPkiCli() {
    this(new ConfigurationLoader(), new SecretResolver(), null, null);
  }

  /**
   * Constructor with explicit output and error writers.
   *
   * @param out writer for standard output
   * @param err writer for standard error
   */
  public WalletPkiCli(PrintWriter out, PrintWriter err) {
    this(new ConfigurationLoader(), new SecretResolver(), out, err);
  }

  /**
   * Constructor with custom dependencies and writers (useful for testing).
   *
   * @param configLoader the configuration loader
   * @param secretResolver the secret resolver
   * @param out writer for standard output
   * @param err writer for standard error
   */
  @SuppressWarnings("unchecked")
  public WalletPkiCli(
      ConfigurationLoader configLoader,
      SecretResolver secretResolver,
      PrintWriter out,
      PrintWriter err) {
    GenerateCommand generateCommand = new GenerateCommand(configLoader, secretResolver);
    IFactory customFactory =
        new IFactory() {
          @Override
          public <K> K create(Class<K> cls) throws Exception {
            if (cls == GenerateCommand.class) {
              return (K) generateCommand;
            }
            return CommandLine.defaultFactory().create(cls);
          }
        };

    this.commandLine = new CommandLine(this, customFactory);
    if (out != null) {
      this.commandLine.setOut(out);
    }
    if (err != null) {
      this.commandLine.setErr(err);
    }
  }

  /**
   * Main method entry point.
   *
   * @param args command-line arguments
   */
  public static void main(String[] args) {
    int exitCode = new WalletPkiCli().execute(args);
    System.exit(exitCode);
  }

  /**
   * Executes the CLI with the provided arguments without terminating the JVM.
   *
   * @param args command-line arguments
   * @return exit code (0 for success)
   */
  public int execute(String... args) {
    return commandLine.execute(args);
  }

  public CommandLine getCommandLine() {
    return commandLine;
  }
}
