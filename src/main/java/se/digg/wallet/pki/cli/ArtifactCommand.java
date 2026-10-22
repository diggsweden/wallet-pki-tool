// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;
import se.digg.wallet.pki.generator.GenerationPlan;
import se.digg.wallet.pki.generator.GenerationReport;
import se.digg.wallet.pki.generator.PkiEngine;
import se.digg.wallet.pki.storage.ArtifactStore;

/** Renders structured results; all lifecycle policy belongs to the generation module. */
@Command(mixinStandardHelpOptions = true,
    description = "Maintain artifacts using a versioned environment configuration.")
final class ArtifactCommand implements Callable<Integer> {
  private final PkiEngine engine;
  private final String command;

  @Spec
  private CommandSpec spec;

  @Option(names = {"-c", "--config"}, description = "Environment YAML file.")
  private Path configuration;

  @Option(names = "--plan", description = "Saved JSON plan to apply without replanning.")
  private Path planFile;

  @Option(names = "--operation", description = "For plan: ensure, renew or rotate.")
  private String operation;

  @Option(names = "--json", description = "Emit a structured report.")
  private boolean json;

  @Parameters(paramLabel = "TARGETS",
      description = "Qualified targets, for example identity:pid-issuer.")
  private List<String> targets = new ArrayList<>();

  ArtifactCommand(PkiEngine engine, String command) {
    this.engine = engine;
    this.command = command;
  }

  @Override
  public Integer call() {
    try {
      if (!"plan".equals(command) && operation != null) {
        throw new IllegalArgumentException("--operation is only accepted by plan");
      }
      if ("apply".equals(command)) {
        if (planFile == null || !targets.isEmpty()) {
          throw new IllegalArgumentException("apply requires --plan and accepts no targets");
        }
        SavedPlan saved = ArtifactStore.JSON.readValue(java.nio.file.Files.readAllBytes(planFile),
            SavedPlan.class);
        if (saved.schemaVersion() != 1 || configuration != null
            && !configuration.toAbsolutePath().normalize().equals(Path.of(saved.configuration()))) {
          throw new IllegalArgumentException("Plan schema or configuration path does not match");
        }
        renderReport(engine.apply(saved.plan()));
        return 0;
      }
      if (configuration == null || planFile != null) {
        throw new IllegalArgumentException("This command requires --config and accepts no --plan");
      }
      if ("verify".equals(command)) {
        if (!targets.isEmpty()) {
          throw new IllegalArgumentException("verify checks the complete committed generation");
        }
        renderReport(engine.verify(configuration));
      } else {
        String selected = "plan".equals(command) ? operation == null ? "ensure" : operation
            : "generate".equals(command) ? "ensure" : command;
        GenerationPlan plan = engine.plan(configuration,
            GenerationPlan.Operation.valueOf(selected.toUpperCase(Locale.ROOT)), targets);
        if ("plan".equals(command)) {
          renderPlan(plan);
        } else {
          renderReport(engine.apply(plan));
        }
      }
      return 0;
    } catch (Exception e) {
      spec.commandLine().getErr().println("Error: " + e.getMessage());
      return 1;
    }
  }

  private void renderPlan(GenerationPlan plan) {
    if (json) {
      Map<String, Object> result = new LinkedHashMap<>();
      result.put("schemaVersion", 1);
      result.put("configuration", plan.configuration().toString());
      result.put("environment", plan.environment());
      result.put("configurationDigest", plan.configurationDigest());
      result.put("baseGeneration", plan.baseGeneration());
      result.put("operation", plan.operation());
      result.put("targets", plan.targets());
      result.put("changes", plan.changes());
      result.put("requiredSecrets", plan.requiredSecrets());
      spec.commandLine().getOut().println(ArtifactStore.JSON.writeValueAsString(result));
    } else {
      spec.commandLine().getOut().println("Environment: " + plan.environment());
      for (var change : plan.changes()) {
        spec.commandLine().getOut().println(change.action() + " " + change.reference()
            + " — " + change.reason());
      }
      spec.commandLine().getOut().println("Required secrets: " + plan.requiredSecrets());
    }
  }

  private record SavedPlan(int schemaVersion, String configuration, String environment,
      String configurationDigest, String baseGeneration, GenerationPlan.Operation operation,
      List<String> targets, List<GenerationPlan.Change> changes, List<String> requiredSecrets) {
    GenerationPlan plan() {
      return new GenerationPlan(Path.of(configuration), environment, configurationDigest,
          baseGeneration, operation, targets, changes, requiredSecrets);
    }
  }

  private void renderReport(GenerationReport report) {
    if (json) {
      spec.commandLine().getOut().println(ArtifactStore.JSON.writeValueAsString(Map.of(
          "environment", report.environment(), "generation", report.generation(),
          "bundle", report.bundle().toString(), "changes", report.changes())));
    } else {
      for (var change : report.changes()) {
        spec.commandLine().getOut().println(change.action() + " " + change.reference());
      }
      spec.commandLine().getOut().println("Bundle: " + report.bundle());
      spec.commandLine().getOut().println("verify".equals(command)
          ? "Artifact verification completed successfully."
          : "Generation completed successfully.");
    }
  }
}
