// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.net.URI;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;

/** PID signing, nonce encryption and request encryption are always provisioned together. */
public record PidIssuerConfig(String keystoreFile, SigningConfig signing,
    Encryption encryption, PasswordSource keystorePassword, Registration registration) {
  public PidIssuerConfig {
    Checks.relativePath(keystoreFile, "pidIssuer.keystoreFile");
    Checks.required(signing, "pidIssuer.signing");
    Checks.required(encryption, "pidIssuer.encryption");
    Checks.required(keystorePassword, "pidIssuer.keystorePassword");
    Checks.required(registration, "pidIssuer.registration");
  }

  public record Encryption(SubjectAlternativeNames subjectAlternativeNames) {
    public Encryption {
      Checks.required(subjectAlternativeNames, "pidIssuer.encryption.subjectAlternativeNames");
    }
  }
  public record Registration(String jwtFile, String jsonFile, String issuer, String subject) {
    public Registration {
      Checks.relativePath(jwtFile, "pidIssuer.registration.jwtFile");
      Checks.relativePath(jsonFile, "pidIssuer.registration.jsonFile");
      if (!URI.create(Checks.text(issuer, "pidIssuer.registration.issuer")).isAbsolute()
          || !URI.create(Checks.text(subject, "pidIssuer.registration.subject")).isAbsolute()) {
        throw new IllegalArgumentException(
            "PID registration issuer and subject must be absolute URIs");
      }
    }
  }
}
