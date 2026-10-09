// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

/**
 * Builds and signs Token Status List JWT tokens (OAuth Status List) for revocation checking.
 */
public class StatusListGenerator {

  /** Pre-computed zlib-deflated and base64url-encoded bitset representing 0 revoked entries. */
  public static final String DEFAULT_EMPTY_STATUS_LIST = "eJxjYBgFo2AUjFQAAAQAAAE";
  public static final Duration DEFAULT_VALIDITY = Duration.ofDays(365);

  private final ObjectMapper objectMapper;
  private final TrustListSigner trustListSigner;

  public StatusListGenerator() {
    this(JsonMapper.builder().build(), new TrustListSigner());
  }

  public StatusListGenerator(ObjectMapper objectMapper, TrustListSigner trustListSigner) {
    this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    this.trustListSigner =
        Objects.requireNonNull(trustListSigner, "trustListSigner must not be null");
  }

  /**
   * Generates and signs a Status List JWT token.
   *
   * @param issuerUrl URI identifier for the status list issuer (iss and sub)
   * @param statusListBits base64url-encoded compressed status list bits
   * @param signingKey private key for signing
   * @param signingCert certificate of the signer
   * @param issuedAt issue timestamp
   * @param validity validity duration
   * @return signed compact Status List JWT string
   */
  public String buildAndSignStatusList(
      String issuerUrl,
      String statusListBits,
      PrivateKey signingKey,
      X509Certificate signingCert,
      Instant issuedAt,
      Duration validity) {
    Objects.requireNonNull(issuerUrl, "issuerUrl must not be null");
    Objects.requireNonNull(signingKey, "signingKey must not be null");
    Objects.requireNonNull(signingCert, "signingCert must not be null");

    Instant iat = issuedAt != null ? issuedAt : Instant.now();
    Duration val = validity != null ? validity : DEFAULT_VALIDITY;
    String bits = statusListBits != null ? statusListBits : DEFAULT_EMPTY_STATUS_LIST;

    StatusListPayload payload =
        new StatusListPayload(
            issuerUrl,
            issuerUrl,
            iat.getEpochSecond(),
            iat.plus(val).getEpochSecond(),
            new StatusListContent(1, bits));

    try {
      String json = objectMapper.writeValueAsString(payload);
      return trustListSigner.signStatusListJwt(json, signingKey, signingCert);
    } catch (JacksonException e) {
      throw new PkiCryptoException("Failed to serialize Status List payload to JSON", e);
    }
  }

  /**
   * Model representing the Status List JWT payload claims.
   */
  public record StatusListPayload(
      @JsonProperty("iss") String iss,
      @JsonProperty("sub") String sub,
      @JsonProperty("iat") long iat,
      @JsonProperty("exp") long exp,
      @JsonProperty("status_list") StatusListContent statusList) {
  }

  /**
   * Model representing the status_list claim content.
   */
  public record StatusListContent(
      @JsonProperty("bits") int bits,
      @JsonProperty("lst") String lst) {
  }
}
