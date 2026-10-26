// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.domain;

import java.net.URI;
import java.util.List;
import org.bouncycastle.util.IPAddress;

/** Explicit SAN categories; DNS names are never interpreted as IP addresses or URIs. */
public record SubjectAlternativeNames(List<String> dns, List<String> ip, List<String> uri) {
  public SubjectAlternativeNames {
    dns = dns == null ? List.of() : List.copyOf(dns);
    ip = ip == null ? List.of() : List.copyOf(ip);
    uri = uri == null ? List.of() : List.copyOf(uri);
    for (String name : dns) {
      if (name.isBlank() || name.contains(":") || name.contains("/") || name.contains(" ")) {
        throw new IllegalArgumentException("Invalid DNS SAN: " + name);
      }
    }
    for (String address : ip) {
      if (!IPAddress.isValid(address)) {
        throw new IllegalArgumentException("Invalid IP SAN: " + address);
      }
    }
    for (String value : uri) {
      if (!URI.create(value).isAbsolute()) {
        throw new IllegalArgumentException("URI SAN must be absolute: " + value);
      }
    }
  }

  public static SubjectAlternativeNames empty() {
    return new SubjectAlternativeNames(List.of(), List.of(), List.of());
  }
}
