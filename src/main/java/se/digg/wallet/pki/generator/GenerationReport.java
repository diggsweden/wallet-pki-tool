// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.generator;

import java.nio.file.Path;
import java.util.List;

/** Published outcome; secret values and private material never enter this interface. */
public record GenerationReport(String environment, String generation, Path bundle,
    List<GenerationPlan.Change> changes) {
  public GenerationReport {
    changes = List.copyOf(changes);
  }
}
