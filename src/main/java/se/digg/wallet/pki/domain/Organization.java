// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.domain;

/** The legal entity operating the wallet participants. */
public record Organization(String name, String country, String identifier) {
  public Organization {
    Checks.text(name, "organization.name");
    Checks.text(identifier, "organization.identifier");
    if (country == null || !country.matches("[A-Z]{2}")) {
      throw new IllegalArgumentException("organization.country must contain two uppercase letters");
    }
  }
}
