// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;

/** Separate access and registration hierarchies for the verifier. */
public record VerifierConfig(Access access, RegistrationSigner registrationSigner,
    SupervisoryAuthority supervisoryAuthority, List<VerifierRegistrationConfig> registrations) {
  public VerifierConfig {
    registrations = registrations == null ? List.of() : List.copyOf(registrations);
    var outputPaths = new HashSet<Path>();
    if (access != null) {
      outputPaths.add(Path.of(access.keystoreFile()).normalize());
    }
    if (registrationSigner != null) {
      addOutputPath(outputPaths, registrationSigner.keystoreFile());
    }
    if (!registrations.isEmpty()) {
      Checks.required(registrationSigner, "verifier.registrationSigner");
      Checks.required(supervisoryAuthority, "verifier.supervisoryAuthority");
    }
    var intendedUseIds = new HashSet<String>();
    for (var registration : registrations) {
      if (!intendedUseIds.add(registration.intendedUseId())) {
        throw new IllegalArgumentException("Duplicate verifier intendedUseId: "
            + registration.intendedUseId());
      }
      addOutputPath(outputPaths, registration.jwtFile());
    }
  }

  private static void addOutputPath(Set<Path> paths, String value) {
    if (!paths.add(Path.of(value).normalize())) {
      throw new IllegalArgumentException("Verifier output paths must be distinct: " + value);
    }
  }

  public record SupervisoryAuthority(String name, String country, String email) {
    public SupervisoryAuthority {
      Checks.text(name, "verifier.supervisoryAuthority.name");
      Checks.text(country, "verifier.supervisoryAuthority.country");
      Checks.text(email, "verifier.supervisoryAuthority.email");
    }
  }

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

  public record RegistrationSigner(String keystoreFile, String keyAlias, String commonName,
      SubjectAlternativeNames subjectAlternativeNames, PasswordSource keystorePassword) {
    public RegistrationSigner {
      Checks.relativePath(keystoreFile, "verifier.registrationSigner.keystoreFile");
      keyAlias = keyAlias == null ? "registration"
          : Checks.text(keyAlias, "verifier.registrationSigner.keyAlias");
      Checks.text(commonName, "verifier.registrationSigner.commonName");
      subjectAlternativeNames = subjectAlternativeNames == null ? SubjectAlternativeNames.empty()
          : subjectAlternativeNames;
      Checks.required(keystorePassword, "verifier.registrationSigner.keystorePassword");
    }
  }
}
