// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.util.ArrayList;
import java.util.List;

/**
 * Test data builder for constructing {@link CertificateConfig} instances with sensible defaults.
 */
public class CertificateConfigTestBuilder {

  private String id = "test-certificate";
  private String type = "service";
  private String ca = "default-ca";
  private String keystore = "./test-certificates/keystore.p12";
  private String passwordEnv = "TEST_KEYSTORE_PASSWORD";
  private String passwordFile;
  private List<String> sans = new ArrayList<>();
  private String tradeName;
  private String country = "SE";
  private String organizationIdentifier;

  /**
   * Creates a new generic certificate builder.
   *
   * @return a new CertificateConfigTestBuilder instance
   */
  public static CertificateConfigTestBuilder builder() {
    return new CertificateConfigTestBuilder();
  }

  /**
   * Creates a preconfigured builder for a Relying Party Access Certificate (WRPAC).
   *
   * @return a configured CertificateConfigTestBuilder instance
   */
  public static CertificateConfigTestBuilder verifierAccessCertificate() {
    return new CertificateConfigTestBuilder()
        .id("verifier-access-certificate")
        .type("relying-party-access")
        .ca("verifier-access-ca")
        .keystore("./verifier-access-certificate/verifier-access-certificate.p12")
        .passwordEnv("TEST_VERIFIER_KEYSTORE_PASSWORD")
        .tradeName("DIGG Verifier")
        .organizationIdentifier("VATSE-12345678")
        .sans(List.of("localhost", "verifier-backend"));
  }

  /**
   * Creates a preconfigured builder for a PID Issuer service certificate.
   *
   * @return a configured CertificateConfigTestBuilder instance
   */
  public static CertificateConfigTestBuilder pidIssuer() {
    return new CertificateConfigTestBuilder()
        .id("pid-issuer")
        .type("pid-issuer-service")
        .ca("pid-issuer-ca")
        .keystore("./issuer/pid_issuer.p12")
        .passwordEnv("TEST_PID_ISSUER_KEYSTORE_PASSWORD")
        .sans(List.of("localhost", "pid-issuer"));
  }

  /**
   * Creates a preconfigured builder for a Wallet Provider service certificate.
   *
   * @return a configured CertificateConfigTestBuilder instance
   */
  public static CertificateConfigTestBuilder walletProvider() {
    return new CertificateConfigTestBuilder()
        .id("wallet-provider")
        .type("wallet-provider-service")
        .ca("wallet-provider-ca")
        .keystore("./wallet-provider/wallet_provider.p12")
        .passwordEnv("TEST_PROVIDER_KEYSTORE_PASSWORD")
        .sans(List.of("localhost", "wallet-provider"));
  }

  public CertificateConfigTestBuilder id(String id) {
    this.id = id;
    return this;
  }

  public CertificateConfigTestBuilder type(String type) {
    this.type = type;
    return this;
  }

  public CertificateConfigTestBuilder ca(String ca) {
    this.ca = ca;
    return this;
  }

  public CertificateConfigTestBuilder keystore(String keystore) {
    this.keystore = keystore;
    return this;
  }

  public CertificateConfigTestBuilder passwordEnv(String passwordEnv) {
    this.passwordEnv = passwordEnv;
    return this;
  }

  public CertificateConfigTestBuilder passwordFile(String passwordFile) {
    this.passwordFile = passwordFile;
    if (passwordFile != null && !passwordFile.isBlank()
        && "TEST_KEYSTORE_PASSWORD".equals(this.passwordEnv)) {
      this.passwordEnv = null;
    }
    return this;
  }

  public CertificateConfigTestBuilder sans(List<String> sans) {
    this.sans = sans != null ? new ArrayList<>(sans) : new ArrayList<>();
    return this;
  }

  public CertificateConfigTestBuilder tradeName(String tradeName) {
    this.tradeName = tradeName;
    return this;
  }

  public CertificateConfigTestBuilder country(String country) {
    this.country = country;
    return this;
  }

  public CertificateConfigTestBuilder organizationIdentifier(String organizationIdentifier) {
    this.organizationIdentifier = organizationIdentifier;
    return this;
  }

  /**
   * Constructs the immutable {@link CertificateConfig} instance.
   *
   * @return a new CertificateConfig object
   */
  public CertificateConfig build() {
    return new CertificateConfig(
        id,
        type,
        ca,
        keystore,
        passwordEnv,
        passwordFile,
        sans,
        tradeName,
        country,
        organizationIdentifier);
  }
}
