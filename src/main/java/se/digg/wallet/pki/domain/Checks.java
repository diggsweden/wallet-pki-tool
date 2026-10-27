// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.domain;

import java.net.URI;
import java.nio.file.Path;

/** Invariants shared by configuration and certificate value objects. */
public final class Checks {
  private Checks() {}

  public static String text(String value, String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " is required");
    }
    return value;
  }

  public static <T> T required(T value, String field) {
    if (value == null) {
      throw new IllegalArgumentException(field + " is required");
    }
    return value;
  }

  public static String httpUrl(String value, String field) {
    URI uri = URI.create(text(value, field));
    if (!("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))
        || uri.getHost() == null || uri.getFragment() != null || uri.getQuery() != null) {
      throw new IllegalArgumentException(
          field + " must be an absolute HTTP(S) URL without query or fragment");
    }
    return value;
  }

  /** Artifact locations are explicit paths relative to the output directory. */
  public static String relativePath(String value, String field) {
    Path path = Path.of(text(value, field)).normalize();
    if (path.isAbsolute() || path.startsWith("..") || path.toString().isEmpty()) {
      throw new IllegalArgumentException(field + " must be a relative path inside outputDirectory");
    }
    return value;
  }

  public static int positive(int value, String field) {
    if (value <= 0) {
      throw new IllegalArgumentException(field + " must be positive");
    }
    return value;
  }
}
