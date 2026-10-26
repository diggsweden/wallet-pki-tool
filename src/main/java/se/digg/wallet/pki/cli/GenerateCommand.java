// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.function.BiConsumer;
import java.util.function.Supplier;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Spec;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.PkiConfiguration;

/** A leaf command calls exactly one named application operation. */
@Command(name = "generate", mixinStandardHelpOptions = true)
final class GenerateCommand implements Callable<Integer> {
  @Spec
  private CommandSpec spec;
  private final ConfigurationLoader loader;
  private final Supplier<Path> configuration;
  private final BiConsumer<PkiConfiguration, PrintWriter> operation;

  GenerateCommand(ConfigurationLoader loader, Supplier<Path> configuration,
      BiConsumer<PkiConfiguration, PrintWriter> operation) {
    this.loader = loader;
    this.configuration = configuration;
    this.operation = operation;
  }

  @Override
  public Integer call() {
    try {
      var config = loader.load(configuration.get());
      operation.accept(config, spec.commandLine().getOut());
      spec.commandLine().getOut().println("Generation completed: " + config.outputDirectory());
      return 0;
    } catch (Exception e) {
      spec.commandLine().getErr().println("Error: " + e.getMessage());
      return 1;
    }
  }
}
