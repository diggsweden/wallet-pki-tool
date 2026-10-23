// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import com.nimbusds.jose.JWSObject;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import se.digg.wallet.pki.config.PidIssuerConfig;
import se.digg.wallet.pki.config.VerifierRegistrationConfig;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.infrastructure.ArtifactWriter;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/** JSON registration documents rendered from explicit placeholders. */
public final class RegistrationDocuments {
  private final ObjectMapper json = JsonMapper.builder().build();
  private final TrustListSigner signer = new TrustListSigner();
  private final ArtifactWriter writer = new ArtifactWriter();

  public void writePidIssuer(PidIssuerConfig.Registration config, SigningIdentity identity,
      Path outputDirectory) {
    String payload = JsonTemplate.render(json, """
        {
          "iss": ${issuer},
          "sub": ${subject}
        }
        """, Map.of("issuer", config.issuer(), "subject", config.subject()));
    String token = signer.signJws(payload, identity.keyPair().getPrivate(),
        identity.certificate(), "rc-wrp+jwt");
    writer.text(outputDirectory.resolve(config.jwtFile()), token);
    try {
      var header = JWSObject.parse(token).getHeader().toJSONObject();
      String document = JsonTemplate.render(json, """
          {
            "headers": ${headers},
            "payload": ${payload}
          }
          """, Map.of("headers", header, "payload", json.readTree(payload)));
      writer.text(outputDirectory.resolve(config.jsonFile()), document);
    } catch (java.text.ParseException e) {
      throw new PkiCryptoException("Cannot serialize PID registration header", e);
    }
  }

  public void writeVerifier(VerifierRegistrationConfig config, Organization organization,
      SigningIdentity identity, CertificateAuthority authority, Path outputDirectory) {
    long issuedAt = Instant.now().getEpochSecond();
    String base = config.publicBaseUrl().replaceAll("/+$", "");
    var claims = config.requestedPidClaims().stream()
        .map(path -> Map.of("path", Arrays.asList(path.split("\\.")))).toList();
    var values = new LinkedHashMap<String, Object>();
    values.put("name", config.name());
    values.put("subject", organization.identifier());
    values.put("country", organization.country());
    values.put("issuedAt", issuedAt);
    values.put("expiresAt", issuedAt + Duration.ofDays(config.validityDays()).toSeconds());
    values.put("registryUri", base + "/registry");
    values.put("description", config.description());
    values.put("purpose", config.purpose());
    values.put("claims", claims);
    values.put("serviceIdentifier", config.serviceIdentifier());
    values.put("intendedUseId", config.intendedUseId());
    values.put("privacyPolicy", base + "/privacy");
    values.put("infoUri", base + "/info");
    values.put("supportUri", base + "/support");
    values.put("supervisoryAuthority", config.supervisoryAuthority());
    values.put("certificatePolicy", base + "/certificate-policy");
    values.put("statusUri", base + "/registration-certificate-status");

    String payload = JsonTemplate.render(json, """
        {
          "name": ${name},
          "sub": ${subject},
          "country": ${country},
          "iat": ${issuedAt},
          "exp": ${expiresAt},
          "registry_uri": ${registryUri},
          "srv_description": ${description},
          "entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
          "purpose": ${purpose},
          "credentials": [
            {
              "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claim": ${claims}
            }
          ],
          "service_identifier": ${serviceIdentifier},
          "intended_use_id": ${intendedUseId},
          "privacy_policy": ${privacyPolicy},
          "info_uri": ${infoUri},
          "support_uri": ${supportUri},
          "supervisory_authority": ${supervisoryAuthority},
          "policy_id": ["0.4.0.19475.3.1"],
          "certificate_policy": ${certificatePolicy},
          "status": {
            "status_list": { "uri": ${statusUri}, "idx": 0 }
          }
        }
        """, values);
    String token = signer.signJws(payload, identity.keyPair().getPrivate(),
        List.of(identity.certificate(), authority.certificate()), "rc-wrp+jwt");
    writer.text(outputDirectory.resolve(config.jwtFile()), token);
    writer.text(outputDirectory.resolve(config.environmentFile()),
        "VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE=" + token + "\n");
  }

}
