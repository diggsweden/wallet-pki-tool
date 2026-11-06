// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.util.List;
import se.digg.wallet.pki.domain.Checks;

/** Business metadata for the verifier's PID registration JWT. */
public record VerifierRegistrationConfig(String jwtFile,
    String name, String serviceIdentifier,
    String intendedUseId,
    String defaultUri, String registryUri, String privacyPolicyUri, String infoUri,
    String supportUri, String certificatePolicyUri, String statusListUri,
    List<LocalizedText> description, List<LocalizedText> purpose,
    List<String> requestedPidClaims, SupervisoryAuthority supervisoryAuthority, int validityDays) {
  public VerifierRegistrationConfig(String jwtFile,
      String name, String serviceIdentifier, String intendedUseId,
      String defaultUri, List<LocalizedText> description, List<LocalizedText> purpose,
      List<String> requestedPidClaims, SupervisoryAuthority supervisoryAuthority,
      int validityDays) {
    this(jwtFile, name, serviceIdentifier, intendedUseId, defaultUri,
        null, null, null, null, null, null, description, purpose, requestedPidClaims,
        supervisoryAuthority, validityDays);
  }

  public VerifierRegistrationConfig {
    Checks.relativePath(jwtFile, "verifier.registration.registration.jwtFile");
    Checks.text(name, "registration.name");
    Checks.text(serviceIdentifier, "registration.serviceIdentifier");
    Checks.text(intendedUseId, "registration.intendedUseId");
    if (defaultUri != null) {
      defaultUri = Checks.httpUrl(defaultUri, "registration.defaultUri");
    }
    registryUri = resolveUri(registryUri, defaultUri, "registration.registryUri");
    privacyPolicyUri = resolveUri(privacyPolicyUri, defaultUri, "registration.privacyPolicyUri");
    infoUri = resolveUri(infoUri, defaultUri, "registration.infoUri");
    supportUri = resolveUri(supportUri, defaultUri, "registration.supportUri");
    certificatePolicyUri =
        resolveUri(certificatePolicyUri, defaultUri, "registration.certificatePolicyUri");
    statusListUri = resolveUri(statusListUri, defaultUri, "registration.statusListUri");
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

  private static String resolveUri(String explicitUri, String defaultUri, String field) {
    if (explicitUri != null) {
      return Checks.httpUrl(explicitUri, field);
    }
    if (defaultUri == null) {
      throw new IllegalArgumentException(
          field + " is required when registration.defaultUri is not set");
    }
    return defaultUri;
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
