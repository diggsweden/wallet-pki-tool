// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.JWSObject;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import se.digg.wallet.pki.config.PidIssuerConfig;
import se.digg.wallet.pki.config.VerifierRegistrationConfig;
import se.digg.wallet.pki.config.VerifierRegistrationConfig.LocalizedText;
import se.digg.wallet.pki.config.VerifierRegistrationConfig.SupervisoryAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.infrastructure.ArtifactWriter;
import se.digg.wallet.pki.infrastructure.EcosystemLayout;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/** Typed registration payloads. Only protocol field names and fixed ecosystem routes live here. */
public final class RegistrationDocuments {
  private final ObjectMapper json = JsonMapper.builder().build();
  private final TrustListSigner signer = new TrustListSigner();
  private final ArtifactWriter writer = new ArtifactWriter();

  public void writePidIssuer(PidIssuerConfig.Registration config, SigningIdentity identity,
      EcosystemLayout layout) {
    var payload = new PidPayload(config.issuer(), config.subject());
    String token = signer.signJws(json.writeValueAsString(payload), identity.keyPair().getPrivate(),
        identity.certificate(), "rc-wrp+jwt");
    writer.text(layout.pidRegistration(), token);
    try {
      var header = JWSObject.parse(token).getHeader().toJSONObject();
      writer.text(layout.pidRegistration().resolveSibling("issuer_wrprc.json"),
          json.writeValueAsString(new PidDocument(header, payload)));
    } catch (java.text.ParseException e) {
      throw new PkiCryptoException("Cannot serialize PID registration header", e);
    }
  }

  public void writeVerifier(VerifierRegistrationConfig config, Organization organization,
      SigningIdentity identity, CertificateAuthority authority, EcosystemLayout layout) {
    long issuedAt = Instant.now().getEpochSecond();
    String base = config.publicBaseUrl().replaceAll("/+$", "");
    var claims = config.requestedPidClaims().stream()
        .map(path -> new RequestedClaim(Arrays.asList(path.split("\\.")))).toList();
    var credentials = List
        .of(new Credential("dc+sd-jwt", new CredentialMetadata(List.of("urn:eudi:pid:1")), claims));
    var payload = new VerifierPayload(config.name(), organization.identifier(),
        organization.country(), issuedAt,
        issuedAt + Duration.ofDays(config.validityDays()).toSeconds(), base + "/registry",
        config.description(),
        List.of("https://uri.etsi.org/19475/Entitlement/Service_Provider"), config.purpose(),
        credentials,
        config.serviceIdentifier(), config.intendedUseId(), base + "/privacy", base + "/info",
        base + "/support",
        config.supervisoryAuthority(), List.of("0.4.0.19475.3.1"), base + "/certificate-policy",
        new Status(new StatusList(base + "/registration-certificate-status", 0)));
    String token = signer.signJws(json.writeValueAsString(payload), identity.keyPair().getPrivate(),
        List.of(identity.certificate(), authority.certificate()), "rc-wrp+jwt");
    writer.text(layout.verifierRegistration(), token);
    writer.text(layout.verifierEnvironment(),
        "VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE=" + token + "\n");
  }

  public record PidPayload(String iss, String sub) {
  }
  public record PidDocument(java.util.Map<String, Object> headers, PidPayload payload) {
  }
  public record RequestedClaim(List<String> path) {
  }
  public record CredentialMetadata(@JsonProperty("vct_values") List<String> vctValues) {
  }
  public record Credential(String format, CredentialMetadata meta, List<RequestedClaim> claim) {
  }
  public record StatusList(String uri, int idx) {
  }
  public record Status(@JsonProperty("status_list") StatusList statusList) {
  }
  public record VerifierPayload(String name, String sub, String country, long iat, long exp,
      @JsonProperty("registry_uri") String registryUri,
      @JsonProperty("srv_description") List<LocalizedText> description,
      List<String> entitlements, List<LocalizedText> purpose, List<Credential> credentials,
      @JsonProperty("service_identifier") String serviceIdentifier,
      @JsonProperty("intended_use_id") String intendedUseId,
      @JsonProperty("privacy_policy") String privacyPolicy,
      @JsonProperty("info_uri") String infoUri,
      @JsonProperty("support_uri") String supportUri,
      @JsonProperty("supervisory_authority") SupervisoryAuthority supervisoryAuthority,
      @JsonProperty("policy_id") List<String> policyId,
      @JsonProperty("certificate_policy") String certificatePolicy, Status status) {
  }
}
