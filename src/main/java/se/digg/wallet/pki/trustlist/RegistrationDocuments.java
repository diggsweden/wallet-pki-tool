// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.JWSObject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Clock;
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
import se.digg.wallet.pki.infrastructure.ArtifactLayout;
import se.digg.wallet.pki.infrastructure.ArtifactWriter;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * Typed registration payloads. Only protocol field names and fixed registration routes live here.
 */
public final class RegistrationDocuments {
  private final Clock clock;

  public RegistrationDocuments(Clock clock) {
    this.clock = clock;
  }

  private final ObjectMapper json = JsonMapper.builder().build();
  private final TrustListSigner signer = new TrustListSigner();
  private final ArtifactWriter writer = new ArtifactWriter();

  public void writePidIssuer(PidIssuerConfig.Registration config, SigningIdentity identity,
      ArtifactLayout layout) {
    var payload = pidPayload(config, identity.certificate(), clock.instant().getEpochSecond());
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
      SigningIdentity identity, CertificateAuthority authority, ArtifactLayout layout) {
    var payload = verifierPayload(config, organization, identity.certificate(),
        clock.instant().getEpochSecond());
    String token = signer.signJws(json.writeValueAsString(payload), identity.keyPair().getPrivate(),
        List.of(identity.certificate(), authority.certificate()), "rc-wrp+jwt");
    writer.text(layout.verifierRegistration(), token);
    writer.text(layout.verifierEnvironment(),
        "VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE=" + token + "\n");
  }

  private VerifierPayload verifierPayload(VerifierRegistrationConfig config,
      Organization organization,
      X509Certificate certificate, long issuedAt) {
    String base = config.publicBaseUrl().replaceAll("/+$", "");
    var claims = config.requestedPidClaims().stream()
        .map(path -> new RequestedClaim(Arrays.asList(path.split("\\.")))).toList();
    var credentials = List
        .of(new Credential("dc+sd-jwt", new CredentialMetadata(List.of("urn:eudi:pid:1")), claims));
    return new VerifierPayload(config.name(), organization.identifier(),
        organization.country(), issuedAt,
        expiry(certificate, issuedAt, config.validityDays()), base + "/registry",
        config.description(),
        List.of("https://uri.etsi.org/19475/Entitlement/Service_Provider"), config.purpose(),
        credentials,
        config.serviceIdentifier(), config.intendedUseId(), base + "/privacy", base + "/info",
        base + "/support",
        config.supervisoryAuthority(), List.of("0.4.0.19475.3.1"), base + "/certificate-policy",
        new Status(new StatusList(base + "/registration-certificate-status", 0)));
  }

  private PidPayload pidPayload(PidIssuerConfig.Registration config, X509Certificate certificate,
      long issuedAt) {
    return new PidPayload(config.issuer(), config.subject(), issuedAt,
        expiry(certificate, issuedAt, 365));
  }

  private static long expiry(X509Certificate certificate, long issuedAt, int days) {
    return Math.min(issuedAt + Duration.ofDays(days).toSeconds(),
        certificate.getNotAfter().toInstant().getEpochSecond());
  }

  public void verifyPid(PidIssuerConfig.Registration config, X509Certificate certificate,
      ArtifactLayout layout) throws Exception {
    var payload = verifyToken(layout.pidRegistration(), List.of(certificate), "rc-wrp+jwt");
    requirePayload(pidPayload(config, certificate, payload.path("iat").asLong()), payload);
  }

  public void verifyVerifier(VerifierRegistrationConfig config, Organization organization,
      X509Certificate certificate,
      CertificateAuthority authority, ArtifactLayout layout) throws Exception {
    var payload = verifyToken(layout.verifierRegistration(),
        List.of(certificate, authority.certificate()), "rc-wrp+jwt");
    requirePayload(verifierPayload(config, organization, certificate, payload.path("iat").asLong()),
        payload);
    if (!Files.readString(layout.verifierEnvironment())
        .equals("VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE="
            + Files.readString(layout.verifierRegistration()) + "\n")) {
      throw new PkiCryptoException("Registration environment export differs from token");
    }
  }

  public tools.jackson.databind.JsonNode verifyToken(Path file, List<X509Certificate> chain,
      String type) throws Exception {
    String token = Files.readString(file);
    var jwt = JWSObject.parse(token);
    var header = jwt.getHeader();
    if (!com.nimbusds.jose.JWSAlgorithm.ES256.equals(header.getAlgorithm())
        || header.getType() == null
        || !type.equals(header.getType().toString()) || header.getX509CertChain() == null
        || header.getX509CertChain().size() != chain.size()) {
      throw new PkiCryptoException("Unexpected signing header: " + file);
    }
    for (int i = 0; i < chain.size(); i++) {
      if (!Arrays.equals(header.getX509CertChain().get(i).decode(), chain.get(i).getEncoded())) {
        throw new PkiCryptoException("Unexpected signing certificate: " + file);
      }
    }
    if (!signer.verifyJws(token, chain.getFirst().getPublicKey())) {
      throw new PkiCryptoException("Invalid signature: " + file);
    }
    var payload = json.readTree(jwt.getPayload().toString());
    if (!type.equals("trustlist+jwt")) {
      long now = clock.instant().getEpochSecond();
      if (payload.path("iat").asLong() > now || payload.path("exp").asLong() <= now
          || payload.path("exp").asLong() > chain.getFirst().getNotAfter().toInstant()
              .getEpochSecond()) {
        throw new PkiCryptoException("Document is outside its validity period: " + file);
      }
    }
    return payload;
  }

  public void requirePayload(Object expected, tools.jackson.databind.JsonNode actual) {
    if (!json.readTree(json.writeValueAsString(expected)).equals(actual)) {
      throw new PkiCryptoException("Signed payload differs from configured wallet contract");
    }
  }

  public static Instant expiresAt(Path path) throws Exception {
    var payload = JsonMapper.builder().build()
        .readTree(JWSObject.parse(Files.readString(path)).getPayload().toString());
    return Instant.ofEpochSecond(payload.path("exp").asLong());
  }


  public record PidPayload(String iss, String sub, long iat, long exp) {
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
