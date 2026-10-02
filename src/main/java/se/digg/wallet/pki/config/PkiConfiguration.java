// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.ArrayList;
import java.util.List;

/** Configuration model representing the root PKI YAML configuration. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class PkiConfiguration {

  private String environment;
  private String outputDir;
  private List<AuthorityConfig> authorities = new ArrayList<>();
  private List<CertificateConfig> certificates = new ArrayList<>();
  private List<TrustListConfig> trustLists = new ArrayList<>();

  /** Default constructor for Jackson. */
  public PkiConfiguration() {}

  public String getEnvironment() {
    return environment;
  }

  public void setEnvironment(String environment) {
    this.environment = environment;
  }

  public String getOutputDir() {
    return outputDir;
  }

  public void setOutputDir(String outputDir) {
    this.outputDir = outputDir;
  }

  public List<AuthorityConfig> getAuthorities() {
    return authorities != null ? new ArrayList<>(authorities) : new ArrayList<>();
  }

  public void setAuthorities(List<AuthorityConfig> authorities) {
    this.authorities = authorities != null ? new ArrayList<>(authorities) : new ArrayList<>();
  }

  public List<CertificateConfig> getCertificates() {
    return certificates != null ? new ArrayList<>(certificates) : new ArrayList<>();
  }

  public void setCertificates(List<CertificateConfig> certificates) {
    this.certificates = certificates != null ? new ArrayList<>(certificates) : new ArrayList<>();
  }

  public List<TrustListConfig> getTrustLists() {
    return trustLists != null ? new ArrayList<>(trustLists) : new ArrayList<>();
  }

  public void setTrustLists(List<TrustListConfig> trustLists) {
    this.trustLists = trustLists != null ? new ArrayList<>(trustLists) : new ArrayList<>();
  }
}
