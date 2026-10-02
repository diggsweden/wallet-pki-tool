// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Configuration model for a Certificate Authority (CA). */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthorityConfig {

  private String id;
  private String commonName;
  private String keyType = "EC_P256";
  private String keyFile;
  private String certFile;

  /** Default constructor for Jackson. */
  public AuthorityConfig() {}

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getCommonName() {
    return commonName;
  }

  public void setCommonName(String commonName) {
    this.commonName = commonName;
  }

  public String getKeyType() {
    return keyType;
  }

  public void setKeyType(String keyType) {
    this.keyType = keyType;
  }

  public String getKeyFile() {
    return keyFile;
  }

  public void setKeyFile(String keyFile) {
    this.keyFile = keyFile;
  }

  public String getCertFile() {
    return certFile;
  }

  public void setCertFile(String certFile) {
    this.certFile = certFile;
  }
}
