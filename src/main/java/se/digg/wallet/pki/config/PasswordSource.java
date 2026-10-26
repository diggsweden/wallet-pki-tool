// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

/** Exactly one password source, with no environment/file fallback. */
public record PasswordSource(String env, String file) {
  public PasswordSource {
    if ((env == null) == (file == null) || (env != null && env.isBlank())
        || (file != null && file.isBlank())) {
      throw new IllegalArgumentException("Password must specify exactly one non-blank env or file");
    }
  }
}
