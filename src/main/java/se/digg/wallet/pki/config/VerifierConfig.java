// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;

/** Separate access and registration hierarchies for the verifier. */
public record VerifierConfig(Access access, Registration registration) {
  public VerifierConfig {
    if (access == null && registration == null) {
      throw new IllegalArgumentException("Configure verifier access or registration");
    }
  }


  public record Access(AuthorityConfig authority, String commonName,
      SubjectAlternativeNames subjectAlternativeNames, PasswordSource keystorePassword) {
    public Access {
      Checks.required(authority, "verifier.access.authority");
      Checks.text(commonName, "verifier.access.commonName");
      subjectAlternativeNames = subjectAlternativeNames == null ? SubjectAlternativeNames.empty()
          : subjectAlternativeNames;
      Checks.required(keystorePassword, "verifier.access.keystorePassword");
    }
  }

  public record Registration(AuthorityConfig authority, String commonName,
      PasswordSource keystorePassword, VerifierRegistrationConfig registration) {
    public Registration {
      Checks.required(authority, "verifier.registration.authority");
      Checks.text(commonName, "verifier.registration.commonName");
      Checks.required(keystorePassword, "verifier.registration.keystorePassword");
      Checks.required(registration, "verifier.registration.registration");
    }
  }
}
