// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;

/** Subject settings; the containing role selects the certificate profile. */
public record SigningConfig(String commonName, SubjectAlternativeNames subjectAlternativeNames) {
  public SigningConfig {
    Checks.text(commonName, "signing.commonName");
    subjectAlternativeNames =
        subjectAlternativeNames == null ? SubjectAlternativeNames.empty() : subjectAlternativeNames;
  }

  public CertificateSubject subject(Organization organization) {
    return new CertificateSubject(commonName, organization, subjectAlternativeNames);
  }
}
