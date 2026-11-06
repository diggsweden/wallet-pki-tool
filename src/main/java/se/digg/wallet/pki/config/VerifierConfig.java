// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;

/** Separate access and registration hierarchies for the verifier. */
public record VerifierConfig(Access access, Registration registration) {
  public record Access(String keystoreFile, String keyAlias, String commonName,
      SubjectAlternativeNames subjectAlternativeNames, PasswordSource keystorePassword) {
    public Access {
      Checks.relativePath(keystoreFile, "verifier.access.keystoreFile");
      keyAlias = keyAlias == null ? "verifier_access_certificate"
          : Checks.text(keyAlias, "verifier.access.keyAlias");
      Checks.text(commonName, "verifier.access.commonName");
      subjectAlternativeNames = subjectAlternativeNames == null ? SubjectAlternativeNames.empty()
          : subjectAlternativeNames;
      Checks.required(keystorePassword, "verifier.access.keystorePassword");
    }
  }

  public record Registration(String keystoreFile, String keyAlias, String commonName,
      SubjectAlternativeNames subjectAlternativeNames,
      PasswordSource keystorePassword, VerifierRegistrationConfig registration) {
    public Registration {
      Checks.relativePath(keystoreFile, "verifier.registration.keystoreFile");
      keyAlias = keyAlias == null ? "registration"
          : Checks.text(keyAlias, "verifier.registration.keyAlias");
      Checks.text(commonName, "verifier.registration.commonName");
      subjectAlternativeNames = subjectAlternativeNames == null ? SubjectAlternativeNames.empty()
          : subjectAlternativeNames;
      Checks.required(keystorePassword, "verifier.registration.keystorePassword");
      Checks.required(registration, "verifier.registration.registration");
    }
  }
}
