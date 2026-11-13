// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import com.nimbusds.jose.JWSObject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.text.ParseException;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

/** Continues the sequence stored in the previous signed LoTE output. */
public final class LoteSequence {
  public long next(Path output) {
    try {
      var token = JWSObject.parse(Files.readString(output));
      var document = JsonMapper.builder().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .build().readTree(token.getPayload().toString());
      var sequence = document.at("/LoTE/ListAndSchemeInformation/LoTESequenceNumber");
      if (!sequence.isIntegralNumber() || !sequence.canConvertToLong() || sequence.asLong() <= 0) {
        throw new PkiCryptoException("Invalid LoTE sequence number in " + output);
      }
      return Math.incrementExact(sequence.asLong());
    } catch (NoSuchFileException e) {
      return 1;
    } catch (IOException | ParseException | JacksonException | ArithmeticException e) {
      throw new PkiCryptoException("Cannot determine next LoTE sequence number from " + output, e);
    }
  }
}
