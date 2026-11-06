// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSObject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.config.PidIssuerConfig;
import se.digg.wallet.pki.config.VerifierRegistrationConfig;
import se.digg.wallet.pki.config.VerifierRegistrationConfig.LocalizedText;
import se.digg.wallet.pki.config.VerifierRegistrationConfig.SupervisoryAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

class RegistrationDocumentsIntegrationTest {
  @TempDir
  Path directory;
  private final tools.jackson.databind.ObjectMapper prettyMapper =
      JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();

  @Test
  void verifier_registration_preserves_the_protocol_document() throws Exception {
    var payload = writeVerifier("Service");
    assertThat(payload.get("iat").isIntegralNumber()).isTrue();
    assertThat(payload.get("exp").asLong() - payload.get("iat").asLong())
        .isEqualTo(Duration.ofDays(30).toSeconds());
    payload.remove("iat");
    payload.remove("exp");
    var expected = JsonMapper.builder().build().readTree("""
        {
          "name": "Service",
          "sub": "VATSE-12345678",
          "country": "SE",
          "registry_uri": "https://example.test/registry",
          "srv_description": [{ "lang": "en", "value": "Service" }],
          "entitlements": ["https://uri.etsi.org/19475/Entitlement/Service_Provider"],
          "purpose": [{ "lang": "en", "value": "Identification" }],
          "credentials": [
            {
              "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eudi:pid:1"] },
              "claim": [
                { "path": ["family_name"] },
                { "path": ["address", "street_address"] }
              ]
            }
          ],
          "service_identifier": "wallet-ecosystem",
          "intended_use_id": "1",
          "privacy_policy": "https://example.test/privacy",
          "info_uri": "https://example.test/info",
          "support_uri": "https://example.test/support",
          "supervisory_authority": {
            "name": "Service", "country": "SE", "email": "help@example.test"
          },
          "policy_id": ["0.4.0.19475.3.1"],
          "certificate_policy": "https://example.test/certificate-policy",
          "status": {
            "status_list": {
              "uri": "https://example.test/registration-certificate-status", "idx": 0
            }
          }
        }
        """);

    assertThat(payload).isEqualTo(expected);
  }

  @Test
  void configured_text_survives_json_escaping_in_the_signed_document() throws Exception {
    String text = "A \"quoted\" name\nC:\\wallet";

    var payload = writeVerifier(text);

    assertThat(payload.get("name").asString()).isEqualTo(text);
    assertThat(payload.at("/srv_description/0/value").asString()).isEqualTo(text);
    assertThat(payload.at("/supervisory_authority/name").asString()).isEqualTo(text);
  }

  @Test
  void explicit_uris_override_public_base_url() throws Exception {
    var config = new VerifierRegistrationConfig("registration.jwt", "Service",
        "wallet-ecosystem", "1", null,
        "https://registry.example.test/r",
        "https://privacy.example.test/p",
        "https://info.example.test/i",
        "https://support.example.test/s",
        "https://policy.example.test/cp",
        "https://status.example.test/sl",
        List.of(new LocalizedText("en", "Service")),
        List.of(new LocalizedText("en", "Identification")),
        List.of("family_name"),
        new SupervisoryAuthority("IMY", "SE", "help@example.test"), 30);
    var organization = new Organization("DIGG", "SE", "VATSE-12345678");
    var authority = new CertificateAuthorityManager().createAuthority("registration", "Test CA");
    var key = new EcKeyGenerator().generateKeyPair();
    var certificate = new CertificateProfileIssuer().issueRelyingPartyRegistrationCertificate(
        new CertificateSubject("Registration", organization, SubjectAlternativeNames.empty()),
        key.getPublic(), authority);

    new RegistrationDocuments().writeVerifier(config, organization,
        new SigningIdentity(key, certificate), authority, directory);

    assertThat(directory.resolve("registration.jwt")).isRegularFile();
    String rawPayload = JWSObject.parse(Files.readString(directory.resolve("registration.jwt")))
        .getPayload().toString();
    var payload = prettyMapper.readTree(rawPayload);
    assertThat(rawPayload).isEqualTo(prettyMapper.writeValueAsString(payload));
    assertThat(payload.get("registry_uri").asString()).isEqualTo("https://registry.example.test/r");
    assertThat(payload.get("privacy_policy").asString())
        .isEqualTo("https://privacy.example.test/p");
    assertThat(payload.get("info_uri").asString()).isEqualTo("https://info.example.test/i");
    assertThat(payload.get("support_uri").asString()).isEqualTo("https://support.example.test/s");
    assertThat(payload.get("certificate_policy").asString())
        .isEqualTo("https://policy.example.test/cp");
    assertThat(payload.at("/status/status_list/uri").asString())
        .isEqualTo("https://status.example.test/sl");
  }

  @Test
  void pid_issuer_registration_json_output_is_pretty_printed() throws Exception {
    var organization = new Organization("DIGG", "SE", "VATSE-12345678");
    var authority = new CertificateAuthorityManager().createAuthority("pid", "PID CA");
    var key = new EcKeyGenerator().generateKeyPair();
    var certificate = new CertificateProfileIssuer().issuePidSigningCertificate(
        new CertificateSubject("PID", organization, SubjectAlternativeNames.empty()),
        key.getPublic(), authority);
    var config =
        new PidIssuerConfig.Registration(null, "issuer_wrprc.json", "did:web:localhost",
            "did:web:localhost");

    new RegistrationDocuments().writePidIssuer(config, new SigningIdentity(key, certificate),
        directory);

    assertThat(directory.resolve("issuer_wrprc.jwt")).doesNotExist();
    String content = Files.readString(directory.resolve("issuer_wrprc.json"));
    assertThat(content).isEqualTo(prettyMapper.writeValueAsString(prettyMapper.readTree(content)));
  }

  private ObjectNode writeVerifier(String name) throws Exception {
    var config = new VerifierRegistrationConfig("registration.jwt", name,
        "wallet-ecosystem", "1", "https://example.test/",
        List.of(new LocalizedText("en", name)),
        List.of(new LocalizedText("en", "Identification")),
        List.of("family_name", "address.street_address"),
        new SupervisoryAuthority(name, "SE", "help@example.test"), 30);
    var organization = new Organization("DIGG", "SE", "VATSE-12345678");
    var authority = new CertificateAuthorityManager().createAuthority("registration", "Test CA");
    var key = new EcKeyGenerator().generateKeyPair();
    var certificate = new CertificateProfileIssuer().issueRelyingPartyRegistrationCertificate(
        new CertificateSubject("Registration", organization, SubjectAlternativeNames.empty()),
        key.getPublic(), authority);
    var identity = new SigningIdentity(key, certificate);

    new RegistrationDocuments().writeVerifier(config, organization, identity, authority, directory);

    String token = Files.readString(directory.resolve(config.jwtFile()));
    assertThat(new TrustListSigner().verifyJws(token, certificate.getPublicKey())).isTrue();
    var document = JWSObject.parse(token);
    assertThat(document.getHeader().getType().toString()).isEqualTo("rc-wrp+jwt");
    assertThat(document.getHeader().getX509CertChain()).hasSize(2);
    String rawPayload = document.getPayload().toString();
    var tree = prettyMapper.readTree(rawPayload);
    assertThat(rawPayload).isEqualTo(prettyMapper.writeValueAsString(tree));
    return (ObjectNode) tree;
  }
}
