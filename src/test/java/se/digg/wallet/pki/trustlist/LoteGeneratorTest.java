// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.config.LoteConfig;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.support.EcosystemFixture;
import tools.jackson.core.json.JsonWriteFeature;
import tools.jackson.databind.json.JsonMapper;

class LoteGeneratorTest {
  @Test
  void roles_determine_service_types_even_when_subject_names_are_misleading(@TempDir Path directory)
      throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var manager = new CertificateAuthorityManager();
    var pid = manager.createAuthority("one", "Wallet provider").certificate();
    var wallet = manager.createAuthority("two", "PID issuer").certificate();
    var access = manager.createAuthority("three", "No role information").certificate();
    var registration = manager.createAuthority("four", "Same generic name").certificate();
    var generator = new LoteGenerator();
    String json =
        generator.buildLoteDocument(List.of(
            new LoteAuthority(AuthorityRole.WALLET_ATTESTATION_ISSUER, wallet,
                config.trustSource().lote().trustedAuthorities().walletAttestationIssuer()
                    .getFirst()),
            new LoteAuthority(AuthorityRole.PID_ISSUER, pid,
                config.trustSource().lote().trustedAuthorities().pidIssuer().getFirst()),
            new LoteAuthority(AuthorityRole.VERIFIER_ACCESS, access,
                config.trustSource().lote().trustedAuthorities().verifierAccess().getFirst()),
            new LoteAuthority(AuthorityRole.VERIFIER_REGISTRATION, registration,
                config.trustSource().lote().trustedAuthorities().verifierRegistration()
                    .getFirst())),
            config.trustSource().lote(), config.organization());
    var document = JsonMapper.builder().build().readTree(json);
    var entities = document.at("/LoTE/TrustedEntitiesList");
    assertThat(entities.size()).isEqualTo(4);
    var serviceTypes = new ArrayList<String>();
    for (int i = 0; i < entities.size(); i++) {
      serviceTypes.add(entities.get(i)
          .at("/TrustedEntityServices/0/ServiceInformation/ServiceTypeIdentifier").asString());
    }
    assertThat(serviceTypes)
        .containsExactly(LoteGenerator.SVC_TYPE_WALLET_ISSUANCE,
            LoteGenerator.SVC_TYPE_PID_ISSUANCE, LoteGenerator.SVC_TYPE_WRPAC_ISSUANCE,
            LoteGenerator.SVC_TYPE_WRPRC_ISSUANCE);
    var expected = List.of(wallet, pid, access, registration);
    for (int i = 0; i < entities.size(); i++) {
      var encoded = entities.get(i)
          .at("/TrustedEntityServices/0/ServiceInformation/"
              + "ServiceDigitalIdentity/X509Certificates/0/val")
          .asString();
      assertThat(Base64.getDecoder().decode(encoded)).isEqualTo(expected.get(i).getEncoded());
    }
    var scheme = document.at("/LoTE/ListAndSchemeInformation");
    assertThat(scheme.at("/SchemeName/0/value").asString()).isEqualTo("Local LoTE");
    assertThat(scheme.get("LoTEVersionIdentifier").asInt()).isEqualTo(1);
    assertThat(scheme.get("LoTEType").asString())
        .isEqualTo(LoteGenerator.LOTE_TYPE_WALLET_PROVIDERS);
    assertThat(Duration.between(Instant.parse(scheme.get("ListIssueDateTime").asString()),
        Instant.parse(scheme.get("NextUpdate").asString()))).isEqualTo(Duration.ofDays(365));
    assertThat(json).contains("\"LoTE\"", "\"TrustedEntitiesList\"", "\"ServiceDigitalIdentity\"");
  }

  @Test
  void supplied_mapper_serialization_settings_are_preserved() {
    var mapper = JsonMapper.builder().enable(JsonWriteFeature.ESCAPE_NON_ASCII).build();
    var generator = new LoteGenerator(mapper, new TrustListSigner());
    var config = new LoteConfig("lote.jwt", "Svensk plånbok", 1, 30,
        new LoteConfig.TrustedAuthorities(null, null, null, null));
    var organization = new Organization("Digg", "SE", "VATSE-12345678");

    String json = generator.buildLoteDocument(List.of(), config, organization);

    assertThat(json).containsIgnoringCase("Svensk pl\\u00e5nbok");
    assertThat(mapper.readTree(json).at("/LoTE/ListAndSchemeInformation/SchemeName/0/value")
        .asString()).isEqualTo("Svensk plånbok");
  }

  @Test
  void configured_text_survives_json_escaping() {
    String text = "A \"quoted\" name\nC:\\wallet";
    var entity = new LoteConfig.Entity(text, text, "https://example.test", text, null);
    var config = new LoteConfig("lote.jwt", text, 7, 30,
        new LoteConfig.TrustedAuthorities(List.of(entity), null, null, null));
    var organization = new Organization(text, "SE", "VATSE-12345678");
    var certificate = new CertificateAuthorityManager().createAuthority("test", "Test CA")
        .certificate();
    var anchors = List.of(new LoteAuthority(AuthorityRole.PID_ISSUER, certificate, entity));
    var generator = new LoteGenerator();

    String json = generator.buildLoteDocument(anchors, config, organization);
    var document = JsonMapper.builder().build().readTree(json);

    var scheme = document.at("/LoTE/ListAndSchemeInformation");
    assertThat(scheme.at("/SchemeOperatorName/0/value").asString()).isEqualTo(text);
    assertThat(scheme.at("/SchemeName/0/value").asString()).isEqualTo(text);
    var information = document.at("/LoTE/TrustedEntitiesList/0/TrustedEntityInformation");
    assertThat(information.at("/TEName/0/value").asString()).isEqualTo(text);
    assertThat(information.at("/TEAddress/TEPostalAddress/0/StreetAddress").asString())
        .isEqualTo(text);
    assertThat(document.at(
        "/LoTE/TrustedEntitiesList/0/TrustedEntityServices/0/"
            + "ServiceInformation/ServiceName/0/value")
        .asString()).isEqualTo(text);
  }
}
