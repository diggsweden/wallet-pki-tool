// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.ArrayList;
import java.util.List;

/** Configuration model for a service certificate. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CertificateConfig {

  private String id;
  private String type;
  private String ca;
  private String keystore;
  private String passwordEnv;
  private String passwordFile;
  private List<String> sans = new ArrayList<>();
  private String tradeName;
  private String country = "SE";
  private String organizationIdentifier;

  /** Default constructor for Jackson. */
  public CertificateConfig() {}

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

  public String getCa() {
    return ca;
  }

  public void setCa(String ca) {
    this.ca = ca;
  }

  public String getKeystore() {
    return keystore;
  }

  public void setKeystore(String keystore) {
    this.keystore = keystore;
  }

  public String getPasswordEnv() {
    return passwordEnv;
  }

  public void setPasswordEnv(String passwordEnv) {
    this.passwordEnv = passwordEnv;
  }

  public String getPasswordFile() {
    return passwordFile;
  }

  public void setPasswordFile(String passwordFile) {
    this.passwordFile = passwordFile;
  }

  public List<String> getSans() {
    return sans != null ? new ArrayList<>(sans) : new ArrayList<>();
  }

  public void setSans(List<String> sans) {
    this.sans = sans != null ? sans : new ArrayList<>();
  }

  public String getTradeName() {
    return tradeName;
  }

  public void setTradeName(String tradeName) {
    this.tradeName = tradeName;
  }

  public String getCountry() {
    return country;
  }

  public void setCountry(String country) {
    this.country = country;
  }

  public String getOrganizationIdentifier() {
    return organizationIdentifier;
  }

  public void setOrganizationIdentifier(String organizationIdentifier) {
    this.organizationIdentifier = organizationIdentifier;
  }
}
