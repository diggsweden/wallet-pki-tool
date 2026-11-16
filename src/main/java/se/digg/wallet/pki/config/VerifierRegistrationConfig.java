// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.net.URI;
import java.util.HashSet;
import java.util.List;
import se.digg.wallet.pki.domain.Checks;

/** Business metadata and credential requests for the verifier's registration JWT. */
public record VerifierRegistrationConfig(String jwtFile,
    String name, String serviceIdentifier,
    String intendedUseId,
    String defaultUri, String registryUri, String privacyPolicyUri, String infoUri,
    String supportUri, String certificatePolicyUri, String statusListUri,
    List<LocalizedText> description, List<LocalizedText> purpose,
    List<RequestedCredential> requestedCredentials, int validityDays) {
  public VerifierRegistrationConfig(String jwtFile,
      String name, String serviceIdentifier, String intendedUseId,
      String defaultUri, List<LocalizedText> description, List<LocalizedText> purpose,
      List<RequestedCredential> requestedCredentials, int validityDays) {
    this(jwtFile, name, serviceIdentifier, intendedUseId, defaultUri,
        null, null, null, null, null, null, description, purpose, requestedCredentials,
        validityDays);
  }

  public VerifierRegistrationConfig {
    Checks.relativePath(jwtFile, "verifier.registrations.jwtFile");
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
    requestedCredentials = List.copyOf(
        Checks.required(requestedCredentials, "registration.requestedCredentials"));
    if (requestedCredentials.isEmpty()) {
      throw new IllegalArgumentException("registration.requestedCredentials must not be empty");
    }
    var vcts = new HashSet<String>();
    for (var credential : requestedCredentials) {
      if (!vcts.add(credential.vct())) {
        throw new IllegalArgumentException(
            "Duplicate requested credential VCT: " + credential.vct());
      }
    }
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

  public record RequestedCredential(String vct, List<String> claims) {
    public RequestedCredential {
      if (!URI.create(Checks.text(vct, "registration.requestedCredentials.vct")).isAbsolute()) {
        throw new IllegalArgumentException(
            "registration.requestedCredentials.vct must be an absolute URI");
      }
      claims = List.copyOf(Checks.texts(claims, "registration.requestedCredentials.claims"));
      for (String claim : claims) {
        if (!claim.matches("[^.\\s]+(\\.[^.\\s]+)*")) {
          throw new IllegalArgumentException("Invalid credential claim path: " + claim);
        }
      }
    }
  }

  public record LocalizedText(String lang, String value) {
    public LocalizedText {
      Checks.text(lang, "localized text.lang");
      Checks.text(value, "localized text.value");
    }
  }
}
