// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.Function;

/** Resolves only the explicitly selected password source. */
public class SecretResolver {
  private final Function<String, String> envProvider;

  public SecretResolver() {
    this(System::getenv);
  }

  public SecretResolver(Function<String, String> envProvider) {
    this.envProvider = Objects.requireNonNull(envProvider);
  }

  public char[] resolve(PasswordSource source) {
    String value;
    if (source.env() != null) {
      value = envProvider.apply(source.env());
    } else {
      try {
        value = Files.readString(Path.of(source.file())).replaceFirst("[\\r\\n]+$", "");
      } catch (IOException e) {
        throw new PkiConfigurationException("Cannot read password file: " + source.file(), e);
      }
    }
    if (value == null || value.isBlank()) {
      throw new PkiConfigurationException("Password source is not set or empty: "
          + (source.env() != null ? source.env() : source.file()));
    }
    return value.toCharArray();
  }
}
