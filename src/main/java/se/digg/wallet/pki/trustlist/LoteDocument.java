// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Root document model for an ETSI TS 119 602 List of Trusted Entities (LoTE).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record LoteDocument(
    @JsonProperty("LoTE") LoteContent lote) {

  public LoteDocument {
    if (lote == null) {
      throw new IllegalArgumentException("lote must not be null");
    }
  }

  /**
   * Inner content of the LoTE document.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record LoteContent(
      @JsonProperty("ListAndSchemeInformation") ListAndSchemeInformation listAndSchemeInformation,
      @JsonProperty("TrustedEntitiesList") List<TrustedEntity> trustedEntitiesList) {

    public LoteContent {
      trustedEntitiesList =
          trustedEntitiesList != null ? List.copyOf(trustedEntitiesList) : List.of();
    }
  }

  /**
   * Scheme and version information for the LoTE.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record ListAndSchemeInformation(
      @JsonProperty("LoTEVersionIdentifier") int loteVersionIdentifier,
      @JsonProperty("LoTESequenceNumber") int loteSequenceNumber,
      @JsonProperty("LoTEType") String loteType,
      @JsonProperty("SchemeOperatorName") List<LangValue> schemeOperatorName,
      @JsonProperty("SchemeName") List<LangValue> schemeName,
      @JsonProperty("SchemeTerritory") String schemeTerritory,
      @JsonProperty("ListIssueDateTime") String listIssueDateTime,
      @JsonProperty("NextUpdate") String nextUpdate) {

    public ListAndSchemeInformation {
      schemeOperatorName = schemeOperatorName != null ? List.copyOf(schemeOperatorName) : List.of();
      schemeName = schemeName != null ? List.copyOf(schemeName) : List.of();
    }
  }

  /**
   * Language-tagged string value.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record LangValue(
      @JsonProperty("lang") String lang,
      @JsonProperty("value") String value) {
  }

  /**
   * Representation of a trusted entity in the LoTE.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record TrustedEntity(
      @JsonProperty("TrustedEntityInformation") TrustedEntityInformation trustedEntityInformation,
      @JsonProperty("TrustedEntityServices") List<TrustedEntityService> trustedEntityServices) {

    public TrustedEntity {
      trustedEntityServices =
          trustedEntityServices != null ? List.copyOf(trustedEntityServices) : List.of();
    }
  }

  /**
   * Information about a trusted entity.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record TrustedEntityInformation(
      @JsonProperty("TEName") List<LangValue> teName,
      @JsonProperty("TEAddress") TeAddress teAddress,
      @JsonProperty("TEInformationURI") List<UriValue> teInformationUri) {

    public TrustedEntityInformation {
      teName = teName != null ? List.copyOf(teName) : List.of();
      teInformationUri = teInformationUri != null ? List.copyOf(teInformationUri) : List.of();
    }
  }

  /**
   * Address information for a trusted entity.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record TeAddress(
      @JsonProperty("TEPostalAddress") List<PostalAddress> tePostalAddress,
      @JsonProperty("TEElectronicAddress") List<UriValue> teElectronicAddress) {

    public TeAddress {
      tePostalAddress = tePostalAddress != null ? List.copyOf(tePostalAddress) : List.of();
      teElectronicAddress =
          teElectronicAddress != null ? List.copyOf(teElectronicAddress) : List.of();
    }
  }

  /**
   * Postal address entry.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record PostalAddress(
      @JsonProperty("lang") String lang,
      @JsonProperty("StreetAddress") String streetAddress,
      @JsonProperty("Country") String country) {
  }

  /**
   * Language-tagged URI value.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record UriValue(
      @JsonProperty("lang") String lang,
      @JsonProperty("uriValue") String uriValue) {
  }

  /**
   * Service provided by a trusted entity.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record TrustedEntityService(
      @JsonProperty("ServiceInformation") ServiceInformation serviceInformation) {
  }

  /**
   * Service information and digital identity details.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record ServiceInformation(
      @JsonProperty("ServiceName") List<LangValue> serviceName,
      @JsonProperty("ServiceDigitalIdentity") ServiceDigitalIdentity serviceDigitalIdentity,
      @JsonProperty("ServiceTypeIdentifier") String serviceTypeIdentifier,
      @JsonProperty("ServiceStatus") String serviceStatus,
      @JsonProperty("StatusStartingTime") String statusStartingTime) {

    public ServiceInformation {
      serviceName = serviceName != null ? List.copyOf(serviceName) : List.of();
    }
  }

  /**
   * Digital identity holding X.509 certificate entries.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record ServiceDigitalIdentity(
      @JsonProperty("X509Certificates") List<X509CertificateVal> x509Certificates) {

    public ServiceDigitalIdentity {
      x509Certificates = x509Certificates != null ? List.copyOf(x509Certificates) : List.of();
    }
  }

  /**
   * Certificate wrapper containing Base64 encoded DER certificate value.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record X509CertificateVal(
      @JsonProperty("val") String val) {
  }
}
