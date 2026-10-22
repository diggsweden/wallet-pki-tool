// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.domain;

/** Validated subject attributes consumed by certificate profile recipes. */
public record CertificateSubject(String commonName, Organization organization,
    SubjectAlternativeNames subjectAlternativeNames) {
  public CertificateSubject {
    Checks.text(commonName, "certificate.commonName");
    Checks.required(organization, "certificate.organization");
    Checks.required(subjectAlternativeNames, "certificate.subjectAlternativeNames");
  }
}
