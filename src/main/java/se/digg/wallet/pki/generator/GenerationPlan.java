// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.generator;

import java.nio.file.Path;
import java.util.List;

/** Read-only description of changes against a particular committed generation. */
public record GenerationPlan(Path configuration, String environment, String configurationDigest,
    String baseGeneration, Operation operation, List<String> targets, List<Change> changes,
    List<String> requiredSecrets) {
  public GenerationPlan {
    targets = List.copyOf(targets);
    changes = List.copyOf(changes);
    requiredSecrets = List.copyOf(requiredSecrets);
  }

  public enum Operation {
    ENSURE, RENEW, ROTATE
  }

  public enum Action {
    CREATE, REUSE, RENEW, ROTATE, REBUILD
  }

  public record Change(String reference, Action action, String reason) {
  }

  public boolean changes(String reference) {
    return changes.stream().anyMatch(c -> c.reference().equals(reference)
        && c.action() != Action.REUSE);
  }
}
