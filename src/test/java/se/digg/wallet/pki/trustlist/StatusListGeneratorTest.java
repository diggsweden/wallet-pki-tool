// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSObject;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;

class StatusListGeneratorTest {

  private StatusListGenerator statusListGenerator;
  private TrustListSigner signer;
  private CertificateAuthorityManager caManager;

  @BeforeEach
  void setUp() {
    statusListGenerator = new StatusListGenerator();
    signer = new TrustListSigner();
    caManager = new CertificateAuthorityManager();
  }

  @Test
  void shouldBuildAndSignStatusListJwt() throws Exception {
    // 1. Setup Trust Source CA
    CertificateAuthority trustSourceCa =
        caManager.createAuthority("trust-source-ca", "DIGG Wallet Trust Source CA");

    String issuerUrl = "http://trust-source/signed/status-list.jwt";
    Instant now = Instant.now();

    // 2. Generate and sign Status List JWT
    String jwt =
        statusListGenerator.buildAndSignStatusList(
            issuerUrl,
            null,
            trustSourceCa.privateKey(),
            trustSourceCa.certificate(),
            now,
            Duration.ofDays(365));

    assertThat(jwt).isNotNull();
    assertThat(jwt.split("\\.")).hasSize(3);

    // 3. Verify header typ is statuslist+jwt
    JWSObject parsed = JWSObject.parse(jwt);
    assertThat(parsed.getHeader().getType()).isNotNull();
    assertThat(parsed.getHeader().getType().toString()).isEqualTo("statuslist+jwt");

    // 4. Verify signature validity
    boolean isValid = signer.verifyJws(jwt, trustSourceCa.publicKey());
    assertThat(isValid).isTrue();

    // 5. Verify payload claims
    String payloadJson = parsed.getPayload().toString();
    assertThat(payloadJson)
        .contains("\"iss\":\"http://trust-source/signed/status-list.jwt\"")
        .contains("\"status_list\"")
        .contains("\"bits\":1")
        .contains("eJxjYBgFo2AUjFQAAAQAAAE");
  }
}
