// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.util.Base64URL;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import se.digg.wallet.pki.crypto.PkiCryptoException;

class LoteSequenceIntegrationTest {
  @TempDir
  Path directory;
  private final LoteSequence sequence = new LoteSequence();

  @Test
  void missing_output_starts_the_sequence_at_one() {
    Path output = directory.resolve("missing/lote.jwt");

    assertThat(sequence.next(output)).isEqualTo(1);
    assertThat(output.getParent()).doesNotExist();
  }

  @ParameterizedTest
  @ValueSource(longs = {1, 42, Integer.MAX_VALUE, Long.MAX_VALUE - 1})
  void an_existing_output_continues_its_sequence(long previous) throws Exception {
    Path output = writePayload(payload(Long.toString(previous)));
    byte[] before = Files.readAllBytes(output);

    assertThat(sequence.next(output)).isEqualTo(previous + 1);
    assertThat(Files.readAllBytes(output)).isEqualTo(before);
  }

  @ParameterizedTest
  @ValueSource(strings = {"null", "0", "-1", "1.5", "\"7\"", "true", "{}", "[]",
      "9223372036854775808", "9223372036854775807"})
  void an_invalid_or_exhausted_sequence_cannot_be_reset(String previous) throws Exception {
    Path output = writePayload(payload(previous));
    byte[] before = Files.readAllBytes(output);

    assertThatThrownBy(() -> sequence.next(output)).isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("LoTE sequence number").hasMessageContaining(output.toString());
    assertThat(Files.readAllBytes(output)).isEqualTo(before);
  }

  @ParameterizedTest
  @ValueSource(strings = {"{}", "null", "", "not-json", "{} {}"})
  void invalid_payloads_cannot_restart_sequences(String payload) throws Exception {
    Path output = writePayload(payload);

    assertThatThrownBy(() -> sequence.next(output)).isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining("LoTE sequence number");
  }

  @Test
  void malformed_tokens_cannot_restart_sequences() throws Exception {
    Path output = directory.resolve("lote.jwt");
    Files.writeString(output, "not-a-jws");

    assertThatThrownBy(() -> sequence.next(output)).isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining(output.toString());
  }

  @Test
  void unreadable_outputs_cannot_restart_sequences() {
    assertThatThrownBy(() -> sequence.next(directory)).isInstanceOf(PkiCryptoException.class)
        .hasMessageContaining(directory.toString());
  }

  private String payload(String previous) {
    return "{\"LoTE\":{\"ListAndSchemeInformation\":{\"LoTESequenceNumber\":" + previous + "}}}";
  }

  private Path writePayload(String payload) throws Exception {
    Path output = directory.resolve("lote.jwt");
    // Only the payload is read; a signature is present to satisfy compact JWS parsing.
    Files.writeString(output, Base64URL.encode("{\"alg\":\"ES256\"}") + "."
        + Base64URL.encode(payload) + ".AA");
    return output;
  }
}
