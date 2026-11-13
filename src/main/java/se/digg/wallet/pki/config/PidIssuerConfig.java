// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.net.URI;
import java.util.stream.Stream;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;

/** PID signing, nonce encryption and request encryption are always provisioned together. */
public record PidIssuerConfig(String keystoreFile, SigningConfig signing,
    Encryption encryption, PasswordSource keystorePassword, Registration registration) {
  public PidIssuerConfig {
    Checks.relativePath(keystoreFile, "pidIssuer.keystoreFile");
    signing = Checks.required(signing, "pidIssuer.signing").withDefaultKeyAlias("pid_issuer");
    encryption = encryption == null ? new Encryption(null, null, SubjectAlternativeNames.empty())
        : encryption;
    if (Stream.of(signing.keyAlias(), encryption.nonceKeyAlias(), encryption.requestKeyAlias())
        .distinct().count() != 3) {
      throw new IllegalArgumentException("pidIssuer key aliases must be distinct");
    }
    Checks.required(keystorePassword, "pidIssuer.keystorePassword");
    Checks.required(registration, "pidIssuer.registration");
  }

  public record Encryption(String nonceKeyAlias, String requestKeyAlias,
      SubjectAlternativeNames subjectAlternativeNames) {
    public Encryption(SubjectAlternativeNames subjectAlternativeNames) {
      this(null, null, subjectAlternativeNames);
    }

    public Encryption {
      nonceKeyAlias = nonceKeyAlias == null ? "nonce-encryption"
          : Checks.text(nonceKeyAlias, "pidIssuer.encryption.nonceKeyAlias");
      requestKeyAlias = requestKeyAlias == null ? "request-encryption"
          : Checks.text(requestKeyAlias, "pidIssuer.encryption.requestKeyAlias");
      subjectAlternativeNames = subjectAlternativeNames == null ? SubjectAlternativeNames.empty()
          : subjectAlternativeNames;
    }
  }

  public record Registration(String jwtFile, String jsonFile, String issuer, String subject) {
    public Registration {
      if (jwtFile == null && jsonFile == null) {
        throw new IllegalArgumentException("At least one of pidIssuer.registration.jwtFile or "
            + "pidIssuer.registration.jsonFile is required");
      }
      if (jwtFile != null) {
        Checks.relativePath(jwtFile, "pidIssuer.registration.jwtFile");
      }
      if (jsonFile != null) {
        Checks.relativePath(jsonFile, "pidIssuer.registration.jsonFile");
      }
      if (!URI.create(Checks.text(issuer, "pidIssuer.registration.issuer")).isAbsolute()
          || !URI.create(Checks.text(subject, "pidIssuer.registration.subject")).isAbsolute()) {
        throw new IllegalArgumentException(
            "PID registration issuer and subject must be absolute URIs");
      }
    }
  }
}
