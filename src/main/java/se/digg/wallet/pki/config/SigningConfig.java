// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;

/** Subject settings; the containing role selects the certificate profile. */
public record SigningConfig(String commonName, String keyAlias,
    SubjectAlternativeNames subjectAlternativeNames) {
  public SigningConfig(String commonName, SubjectAlternativeNames subjectAlternativeNames) {
    this(commonName, null, subjectAlternativeNames);
  }

  public SigningConfig {
    Checks.text(commonName, "signing.commonName");
    if (keyAlias != null) {
      Checks.text(keyAlias, "signing.keyAlias");
    }
    subjectAlternativeNames =
        subjectAlternativeNames == null ? SubjectAlternativeNames.empty() : subjectAlternativeNames;
  }

  public SigningConfig withDefaultKeyAlias(String defaultAlias) {
    return keyAlias == null ? new SigningConfig(commonName, defaultAlias, subjectAlternativeNames)
        : this;
  }

  public CertificateSubject subject(Organization organization) {
    return new CertificateSubject(commonName, organization, subjectAlternativeNames);
  }
}
