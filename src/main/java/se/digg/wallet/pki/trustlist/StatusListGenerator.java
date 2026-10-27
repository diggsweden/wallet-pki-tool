// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import se.digg.wallet.pki.domain.SigningIdentity;
import tools.jackson.databind.json.JsonMapper;

/** Builds and signs the development status-list fixture with all entries valid. */
public final class StatusListGenerator {
  // 8,192 one-bit status entries, all valid (zero), compressed with zlib.
  private static final String COMPRESSED_VALID_STATUSES = "eJxjYBgFo2AUjFQAAAQAAAE";
  private final JsonMapper objectMapper = JsonMapper.builder().build();
  private final TrustListSigner trustListSigner = new TrustListSigner();

  public String buildStatusListDocument(String url, int validityDays) {
    Instant issuedAt = Instant.now();
    var values = new LinkedHashMap<String, Object>();
    values.put("url", url);
    values.put("issuedAt", issuedAt.getEpochSecond());
    values.put("expiresAt", issuedAt.plus(Duration.ofDays(validityDays)).getEpochSecond());
    values.put("statuses", COMPRESSED_VALID_STATUSES);

    return JsonTemplate.render(objectMapper, """
        {
          "iss": ${url},
          "sub": ${url},
          "iat": ${issuedAt},
          "exp": ${expiresAt},
          "status_list": {
            "bits": 1,
            "lst": ${statuses}
          }
        }
        """, values);
  }

  public String sign(String document, SigningIdentity signer) {
    return trustListSigner.signJws(document, signer.keyPair().getPrivate(),
        signer.certificate(), "statuslist+jwt");
  }
}
