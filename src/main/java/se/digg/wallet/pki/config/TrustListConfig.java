// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Configuration model for a trust list (such as LoTE). */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TrustListConfig {

  private String id;
  private String type;
  private String signerAuthority;
  private String outputFile;

  /** Default constructor for Jackson. */
  public TrustListConfig() {}

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getType() {
    return type;
  }

  public void setType(String type) {
    this.type = type;
  }

  public String getSignerAuthority() {
    return signerAuthority;
  }

  public void setSignerAuthority(String signerAuthority) {
    this.signerAuthority = signerAuthority;
  }

  public String getOutputFile() {
    return outputFile;
  }

  public void setOutputFile(String outputFile) {
    this.outputFile = outputFile;
  }
}
