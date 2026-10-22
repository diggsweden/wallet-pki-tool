// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;

/** Separate access and registration hierarchies for the verifier. */
public record VerifierConfig(Access access, Registration registration) {
  public VerifierConfig {
    Checks.required(access, "verifier.access");
    Checks.required(registration, "verifier.registration");
  }

  public record Access(String keystoreFile, String commonName,
      SubjectAlternativeNames subjectAlternativeNames, PasswordSource keystorePassword) {
    public Access {
      Checks.relativePath(keystoreFile, "verifier.access.keystoreFile");
      Checks.text(commonName, "verifier.access.commonName");
      subjectAlternativeNames = subjectAlternativeNames == null ? SubjectAlternativeNames.empty()
          : subjectAlternativeNames;
      Checks.required(keystorePassword, "verifier.access.keystorePassword");
    }
  }
  public record Registration(String keystoreFile, String commonName,
      PasswordSource keystorePassword, VerifierRegistrationConfig registration) {
    public Registration {
      Checks.relativePath(keystoreFile, "verifier.registration.keystoreFile");
      Checks.text(commonName, "verifier.registration.commonName");
      Checks.required(keystorePassword, "verifier.registration.keystorePassword");
      Checks.required(registration, "verifier.registration.registration");
    }
  }
}
