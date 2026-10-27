// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.crypto.PkiCryptoException;

class TrustListSignerTest {
  private final TrustListSigner signer = new TrustListSigner();
  private final EcKeyGenerator keys = new EcKeyGenerator();

  @Test
  void signed_tokens_preserve_the_payload_and_identify_the_signing_certificate() throws Exception {
    var authority = new CertificateAuthorityManager().createAuthority("trust-source", "Test CA");
    String payload = "{\"message\":\"test-lote-payload\"}";

    String token = signer.signJws(payload, authority.privateKey(), authority.certificate());

    var parsed = JWSObject.parse(token);
    assertThat(parsed.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
    assertThat(parsed.getHeader().getType().toString()).isEqualTo("trustlist+jwt");
    assertThat(parsed.getHeader().getX509CertChain()).hasSize(1);
    assertThat(parsed.getHeader().getX509CertChain().getFirst().decode())
        .isEqualTo(authority.certificate().getEncoded());
    assertThat(parsed.getPayload().toString()).isEqualTo(payload);
    assertThat(signer.verifyJws(token, authority.publicKey())).isTrue();
  }

  @Test
  void signatures_are_rejected_with_unrelated_public_keys() {
    var authority = new CertificateAuthorityManager().createAuthority("trust-source", "Test CA");
    String token = signer.signJws("{}", authority.privateKey(), authority.certificate());

    assertThat(signer.verifyJws(token, keys.generateKeyPair().getPublic())).isFalse();
  }

  @ParameterizedTest
  @ValueSource(ints = {1, 2})
  void modified_payloads_or_signatures_fail_verification(int segment) {
    var authority = new CertificateAuthorityManager().createAuthority("trust-source", "Test CA");
    String token = signer.signJws("{\"message\":\"original\"}",
        authority.privateKey(), authority.certificate());
    String[] parts = token.split("\\.");
    byte[] bytes = Base64.getUrlDecoder().decode(parts[segment]);
    bytes[0] ^= 1;
    parts[segment] = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

    assertThat(signer.verifyJws(String.join(".", parts), authority.publicKey())).isFalse();
  }

  @Test
  void malformed_tokens_report_parse_errors() {
    var key = keys.generateKeyPair().getPublic();

    assertThatThrownBy(() -> signer.verifyJws("not-a-valid-jws-token", key))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Failed to verify JWS token");
  }
}
