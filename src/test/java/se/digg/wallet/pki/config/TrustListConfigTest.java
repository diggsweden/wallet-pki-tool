// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

class TrustListConfigTest {

  @Test
  void shouldCreateValidTrustListConfigWithDefaults() {
    TrustListConfig config =
        new TrustListConfig("my-lote", null, "signer-ca", "out.jwt");

    assertThat(config.id()).isEqualTo("my-lote");
    assertThat(config.type()).isEqualTo("etsi-119-602-lote");
    assertThat(config.signerAuthority()).isEqualTo("signer-ca");
    assertThat(config.outputFile()).isEqualTo("out.jwt");
    assertThat(config.url()).isNull();
    assertThat(config.entities()).isEmpty();
  }

  @Test
  void shouldCreateValidTrustListConfigWithFullFields() {
    TrustListConfig config =
        new TrustListConfig(
            "my-status-list",
            "oauth-status-list",
            "signer-ca",
            "out.jwt",
            "https://trust.example.se/status-list.jwt",
            List.of("wallet-provider", "pid-issuer"));

    assertThat(config.id()).isEqualTo("my-status-list");
    assertThat(config.type()).isEqualTo("oauth-status-list");
    assertThat(config.url()).isEqualTo("https://trust.example.se/status-list.jwt");
    assertThat(config.entities()).containsExactly("wallet-provider", "pid-issuer");
  }

  @Test
  void shouldRejectBlankId() {
    assertThatThrownBy(() -> new TrustListConfig("", "etsi-119-602-lote", "ca", "out.jwt"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Trust list 'id' is required and cannot be blank");
  }

  @Test
  void shouldRejectBlankSignerAuthority() {
    assertThatThrownBy(() -> new TrustListConfig("lote", "etsi-119-602-lote", " ", "out.jwt"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Trust list 'signerAuthority' is required for: lote");
  }

  @Test
  void shouldRejectBlankOutputFile() {
    assertThatThrownBy(() -> new TrustListConfig("lote", "etsi-119-602-lote", "ca", ""))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Trust list 'outputFile' is required for: lote");
  }

  @Test
  void shouldRejectUnsupportedType() {
    assertThatThrownBy(() -> new TrustListConfig("lote", "unsupported-type", "ca", "out.jwt"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unsupported trust list type 'unsupported-type' for: lote");
  }
}
