// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.util.List;
import se.digg.wallet.pki.domain.Checks;

/** Business metadata for the verifier's PID registration JWT. */
public record VerifierRegistrationConfig(String jwtFile, String environmentFile,
    String name, String serviceIdentifier,
    String intendedUseId,
    String publicBaseUrl, List<LocalizedText> description, List<LocalizedText> purpose,
    List<String> requestedPidClaims, SupervisoryAuthority supervisoryAuthority, int validityDays) {
  public VerifierRegistrationConfig {
    Checks.relativePath(jwtFile, "verifier.registration.registration.jwtFile");
    Checks.relativePath(environmentFile, "verifier.registration.registration.environmentFile");
    Checks.text(name, "registration.name");
    Checks.text(serviceIdentifier, "registration.serviceIdentifier");
    Checks.text(intendedUseId, "registration.intendedUseId");
    Checks.httpUrl(publicBaseUrl, "registration.publicBaseUrl");
    description = List.copyOf(Checks.required(description, "registration.description"));
    purpose = List.copyOf(Checks.required(purpose, "registration.purpose"));
    if (description.isEmpty() || purpose.isEmpty()) {
      throw new IllegalArgumentException("Registration description and purpose must not be empty");
    }
    requestedPidClaims =
        List.copyOf(Checks.texts(requestedPidClaims, "registration.requestedPidClaims"));
    for (String claim : requestedPidClaims) {
      if (!claim.matches("[a-z_]+(\\.[a-z_]+)*")) {
        throw new IllegalArgumentException("Invalid PID claim path: " + claim);
      }
    }
    Checks.required(supervisoryAuthority, "registration.supervisoryAuthority");
    Checks.positive(validityDays, "registration.validityDays");
  }

  public record LocalizedText(String lang, String value) {
    public LocalizedText {
      Checks.text(lang, "localized text.lang");
      Checks.text(value, "localized text.value");
    }
  }

  public record SupervisoryAuthority(String name, String country, String email) {
    public SupervisoryAuthority {
      Checks.text(name, "supervisoryAuthority.name");
      Checks.text(country, "supervisoryAuthority.country");
      Checks.text(email, "supervisoryAuthority.email");
    }
  }
}
