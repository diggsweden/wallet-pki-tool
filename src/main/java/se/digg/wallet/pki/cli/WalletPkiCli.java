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
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import se.digg.wallet.pki.application.WalletPkiGenerator;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.domain.WalletRole;
import tools.jackson.databind.json.JsonMapper;

/** Explicit authority initialization and generation of fixed wallet-role artifacts. */
@Command(name = "wallet-pki", mixinStandardHelpOptions = true, version = "wallet-pki 0.1.0",
    description = "Generate certificates and signed documents for wallet participants.")
public final class WalletPkiCli {
  private final CommandLine commandLine;

  public WalletPkiCli() {
    this(new SecretResolver(), Clock.systemUTC(), null, null);
  }

  public WalletPkiCli(PrintWriter out, PrintWriter err) {
    this(new SecretResolver(), Clock.systemUTC(), out, err);
  }

  public WalletPkiCli(SecretResolver secrets, Clock clock, PrintWriter out, PrintWriter err) {
    var generator = new WalletPkiGenerator(secrets, clock);
    commandLine = new CommandLine(this)
        .addSubcommand("init-authorities", new InitializeCommand(generator))
        .addSubcommand("generate", new GenerateCommand(generator))
        .addSubcommand("help", new CommandLine.HelpCommand());
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

  private static final class Inputs {
    @Option(names = {"-c", "--config"}, required = true,
        description = "Wallet participant YAML configuration.")
    private Path configuration;
    @Option(names = "--json", description = "Print a structured result.")
    private boolean json;
    @Parameters(paramLabel = "ROLES",
        description = "Selected wallet roles; defaults to all configured roles.")
    private List<String> roles = new ArrayList<>();
  }

  @Command(mixinStandardHelpOptions = true,
      description = "Create absent managed authorities; preserve and validate existing material.")
  private static final class InitializeCommand implements Callable<Integer> {
    @Spec
    private CommandSpec spec;
    @Mixin
    private Inputs inputs = new Inputs();
    private final WalletPkiGenerator generator;

    InitializeCommand(WalletPkiGenerator generator) {
      this.generator = generator;
    }

    @Override
    public Integer call() {
      try {
        var roles = generator.initializeAuthorities(inputs.configuration, inputs.roles).stream()
            .sorted().map(WalletRole::argument).toList();
        if (inputs.json) {
          spec.commandLine().getOut().println(
              JsonMapper.builder().build().writeValueAsString(Map.of("authorities", roles)));
        } else {
          roles.forEach(role -> spec.commandLine().getOut().println("Authority ready: " + role));
        }
        return 0;
      } catch (Exception e) {
        spec.commandLine().getErr().println("Error: " + e.getMessage());
        return 1;
      }
    }
  }

  @Command(mixinStandardHelpOptions = true,
      description = "Generate fresh participant keys and validated artifacts into a new directory.")
  private static final class GenerateCommand implements Callable<Integer> {
    @Spec
    private CommandSpec spec;
    @Mixin
    private Inputs inputs = new Inputs();
    @Option(names = {"-o", "--output"},
        description = "Fresh output directory; overrides outputDirectory from YAML.")
    private Path output;
    private final WalletPkiGenerator generator;

    GenerateCommand(WalletPkiGenerator generator) {
      this.generator = generator;
    }

    @Override
    public Integer call() {
      try {
        var result = generator.generate(inputs.configuration, inputs.roles, output);
        var roles = result.roles().stream().sorted().map(WalletRole::argument).toList();
        if (inputs.json) {
          spec.commandLine().getOut().println(JsonMapper.builder().build().writeValueAsString(
              Map.of("directory", result.directory().toString(), "roles", roles)));
        } else {
          roles.forEach(role -> spec.commandLine().getOut().println("Generated: " + role));
          spec.commandLine().getOut().println("Output: " + result.directory());
        }
        return 0;
      } catch (Exception e) {
        spec.commandLine().getErr().println("Error: " + e.getMessage());
        return 1;
      }
    }
  }
}
