// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import static org.assertj.core.api.Assertions.assertThat;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.domain.WalletTrustAnchors;
import se.digg.wallet.pki.support.EcosystemFixture;

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
    var document =
        generator.buildLoteDocument(new WalletTrustAnchors(pid, wallet, access, registration),
            config.trustSource().lote(), config.organization());
    var entities = document.lote().trustedEntitiesList();
    assertThat(entities).hasSize(4);
    assertThat(entities)
        .extracting(entity -> entity.trustedEntityServices().getFirst().serviceInformation()
            .serviceTypeIdentifier())
        .containsExactly(LoteGenerator.SVC_TYPE_WALLET_ISSUANCE,
            LoteGenerator.SVC_TYPE_PID_ISSUANCE, LoteGenerator.SVC_TYPE_WRPAC_ISSUANCE,
            LoteGenerator.SVC_TYPE_WRPRC_ISSUANCE);
    var expected = List.of(wallet, pid, access, registration);
    for (int i = 0; i < entities.size(); i++) {
      var encoded = entities.get(i).trustedEntityServices().getFirst().serviceInformation()
          .serviceDigitalIdentity().x509Certificates().getFirst().val();
      assertThat(Base64.getDecoder().decode(encoded)).isEqualTo(expected.get(i).getEncoded());
    }
    var scheme = document.lote().listAndSchemeInformation();
    assertThat(scheme.schemeName().getFirst().value()).isEqualTo("Local LoTE");
    assertThat(Duration.between(Instant.parse(scheme.listIssueDateTime()),
        Instant.parse(scheme.nextUpdate()))).isEqualTo(Duration.ofDays(365));
    String json = generator.serializeLoteJson(document);
    assertThat(json).contains("\"LoTE\"", "\"TrustedEntitiesList\"", "\"ServiceDigitalIdentity\"");
  }
}
