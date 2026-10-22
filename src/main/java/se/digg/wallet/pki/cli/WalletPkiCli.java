// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import java.io.PrintWriter;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import se.digg.wallet.pki.generator.PkiEngine;

/** Composition root and argument-to-operation adapter. */
@Command(name = "wallet-pki", mixinStandardHelpOptions = true, version = "wallet-pki 0.1.0",
    description = "Plan, maintain and verify wallet environment trust artifacts.")
public final class WalletPkiCli {
  private final CommandLine commandLine;

  public WalletPkiCli() {
    this(new PkiEngine(), null, null);
  }

  public WalletPkiCli(PrintWriter out, PrintWriter err) {
    this(new PkiEngine(), out, err);
  }

  public WalletPkiCli(PkiEngine engine, PrintWriter out, PrintWriter err) {
    commandLine = new CommandLine(this);
    for (String name : java.util.List.of("plan", "apply", "ensure", "renew", "rotate", "verify",
        "generate")) {
      commandLine.addSubcommand(name, new ArtifactCommand(engine, name));
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
}
