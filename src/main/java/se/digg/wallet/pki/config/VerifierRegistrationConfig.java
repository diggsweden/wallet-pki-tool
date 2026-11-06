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
    String publicBaseUrl, String registryUri, String privacyPolicyUri, String infoUri,
    String supportUri, String certificatePolicyUri, String statusListUri,
    List<LocalizedText> description, List<LocalizedText> purpose,
    List<String> requestedPidClaims, SupervisoryAuthority supervisoryAuthority, int validityDays) {
  public VerifierRegistrationConfig(String jwtFile,
      String name, String serviceIdentifier, String intendedUseId,
      String publicBaseUrl, List<LocalizedText> description, List<LocalizedText> purpose,
      List<String> requestedPidClaims, SupervisoryAuthority supervisoryAuthority,
      int validityDays) {
    this(jwtFile, name, serviceIdentifier, intendedUseId, publicBaseUrl,
        null, null, null, null, null, null, description, purpose, requestedPidClaims,
        supervisoryAuthority, validityDays);
  }

  public VerifierRegistrationConfig {
    Checks.relativePath(jwtFile, "verifier.registration.registration.jwtFile");
    Checks.text(name, "registration.name");
    Checks.text(serviceIdentifier, "registration.serviceIdentifier");
    Checks.text(intendedUseId, "registration.intendedUseId");
    String base = null;
    if (publicBaseUrl != null) {
      Checks.httpUrl(publicBaseUrl, "registration.publicBaseUrl");
      base = publicBaseUrl.replaceAll("/+$", "");
    }
    registryUri = resolveUri(registryUri, base, "/registry", "registration.registryUri");
    privacyPolicyUri =
        resolveUri(privacyPolicyUri, base, "/privacy", "registration.privacyPolicyUri");
    infoUri = resolveUri(infoUri, base, "/info", "registration.infoUri");
    supportUri = resolveUri(supportUri, base, "/support", "registration.supportUri");
    certificatePolicyUri = resolveUri(certificatePolicyUri, base, "/certificate-policy",
        "registration.certificatePolicyUri");
    statusListUri = resolveUri(statusListUri, base, "/registration-certificate-status",
        "registration.statusListUri");
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

  private static String resolveUri(String explicitUri, String base, String defaultSuffix,
      String field) {
    if (explicitUri != null) {
      return Checks.httpUrl(explicitUri, field);
    }
    if (base == null) {
      throw new IllegalArgumentException(
          field + " is required when registration.publicBaseUrl is not set");
    }
    return base + defaultSuffix;
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
