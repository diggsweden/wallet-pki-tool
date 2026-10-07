// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSObject;
import java.security.KeyPair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.crypto.PkiCryptoException;

class TrustListSignerTest {

  private TrustListSigner signer;
  private CertificateAuthorityManager caManager;
  private EcKeyGenerator keyGenerator;

  @BeforeEach
  void setUp() {
    signer = new TrustListSigner();
    caManager = new CertificateAuthorityManager();
    keyGenerator = new EcKeyGenerator();
  }

  @Test
  void shouldSignAndVerifyJwsWithTrustlistJwtType() throws Exception {
    // 1. Setup Trust Source CA
    CertificateAuthority trustSourceCa =
        caManager.createAuthority("trust-source-ca", "DIGG Wallet Trust Source CA");

    String samplePayload = "{\"message\":\"test-lote-payload\"}";

    // 2. Sign payload as compact JWS (default typ: trustlist+jwt)
    String compactJws =
        signer.signJws(
            samplePayload,
            trustSourceCa.privateKey(),
            trustSourceCa.certificate());

    assertThat(compactJws).isNotNull();
    assertThat(compactJws.split("\\.")).hasSize(3);

    // 3. Extract and verify typ and x5c certificate from header
    JWSObject parsed = JWSObject.parse(compactJws);
    assertThat(parsed.getHeader().getType()).isNotNull();
    assertThat(parsed.getHeader().getType().toString()).isEqualTo("trustlist+jwt");

    String certB64 = signer.extractCertificateBase64(compactJws);
    assertThat(certB64).isNotEmpty();

    // 4. Verify cryptographic signature with signer's public key
    boolean isValid = signer.verifyJws(compactJws, trustSourceCa.publicKey());
    assertThat(isValid).isTrue();

    // Verify JWS payload matches original string
    assertThat(parsed.getPayload().toString()).isEqualTo(samplePayload);
  }

  @Test
  void shouldSignStatusListJwtWithStatuslistJwtType() throws Exception {
    CertificateAuthority trustSourceCa =
        caManager.createAuthority("trust-source-ca", "DIGG Wallet Trust Source CA");

    String samplePayload = "{\"iss\":\"http://example.se\",\"status_list\":{}}";

    String compactJwt =
        signer.signStatusListJwt(
            samplePayload,
            trustSourceCa.privateKey(),
            trustSourceCa.certificate());

    JWSObject parsed = JWSObject.parse(compactJwt);
    assertThat(parsed.getHeader().getType()).isNotNull();
    assertThat(parsed.getHeader().getType().toString()).isEqualTo("statuslist+jwt");
    assertThat(signer.verifyJws(compactJwt, trustSourceCa.publicKey())).isTrue();
  }

  @Test
  void shouldRejectTamperedSignature() {
    // 1. Setup two different CAs
    CertificateAuthority ca1 = caManager.createAuthority("ca-1", "CA One");
    CertificateAuthority ca2 = caManager.createAuthority("ca-2", "CA Two");

    String samplePayload = "{\"message\":\"hello\"}";

    // 2. Sign with ca1
    String compactJws =
        signer.signJws(samplePayload, ca1.privateKey(), ca1.certificate());

    // 3. Verify against ca2's public key (must fail)
    boolean isValid = signer.verifyJws(compactJws, ca2.publicKey());
    assertThat(isValid).isFalse();
  }

  @Test
  void shouldThrowWhenParsingInvalidJws() {
    KeyPair keyPair = keyGenerator.generateKeyPair();

    assertThatThrownBy(() -> signer.verifyJws("not-a-valid-jws-token", keyPair.getPublic()))
        .isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("Failed to verify JWS token");
  }
}
