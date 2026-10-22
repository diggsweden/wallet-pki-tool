// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
import java.io.ByteArrayInputStream;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.InflaterInputStream;
import se.digg.wallet.pki.config.EnvironmentConfiguration.Document;
import se.digg.wallet.pki.crypto.IdentityIssuer.SigningIdentity;
import se.digg.wallet.pki.crypto.PkiCryptoException;
import se.digg.wallet.pki.storage.ArtifactStore;

/** Builds protocol documents from explicit identities and entity roles. */
public final class SignedDocumentGenerator {
  public static final String EMPTY_STATUS_BITS = "eJxjYBgFo2AUjFQAAAQAAAE";
  private static final String SERVICE_BASE = "http://uri.etsi.org/19602/SvcType/";
  private final Clock clock;
  private final TrustListSigner signer;

  public SignedDocumentGenerator(Clock clock, TrustListSigner signer) {
    this.clock = clock;
    this.signer = signer;
  }

  public record SignedDocument(String token, Instant expiresAt) {
  }

  public SignedDocument generate(Document document, SigningIdentity identity,
      Map<String, X509Certificate> certificates, int sequence) throws Exception {
    Instant issuedAt = clock.instant().truncatedTo(ChronoUnit.SECONDS);
    Instant expiry = expiry(document, identity.chain().getFirst(), issuedAt);
    String payload = ArtifactStore.JSON.writeValueAsString(payload(document,
        identity.chain().getFirst(), certificates, issuedAt, sequence));
    String token = signer.signJws(payload, identity.key(), identity.chain(), type(document));
    verify(document, token, identity.chain(), certificates);
    return new SignedDocument(token, expiry);
  }

  public void verify(Document document, String token, List<X509Certificate> chain,
      Map<String, X509Certificate> certificates) throws Exception {
    JWSObject jws = JWSObject.parse(token);
    var header = jws.getHeader();
    if (!JWSAlgorithm.ES256.equals(header.getAlgorithm()) || header.getType() == null
        || !type(document).equals(header.getType().toString())
        || header.getX509CertChain() == null || header.getX509CertChain().size() != chain.size()) {
      throw new PkiCryptoException("Invalid signing header for document " + document.id());
    }
    for (int i = 0; i < chain.size(); i++) {
      if (!java.security.MessageDigest.isEqual(header.getX509CertChain().get(i).decode(),
          chain.get(i).getEncoded())) {
        throw new PkiCryptoException("Unexpected signing chain for document " + document.id());
      }
    }
    if (!signer.verifyJws(token, chain.getFirst().getPublicKey())) {
      throw new PkiCryptoException("Invalid signature for document " + document.id());
    }
    var actual = ArtifactStore.JSON.readTree(jws.getPayload().toString());
    Instant issuedAt;
    Instant expiresAt;
    int sequence = 1;
    if ("lote".equals(document.type())) {
      var information = actual.path("LoTE").path("ListAndSchemeInformation");
      issuedAt = Instant.parse(information.path("ListIssueDateTime").asText());
      expiresAt = Instant.parse(information.path("NextUpdate").asText());
      sequence = information.path("LoTESequenceNumber").asInt();
      if (sequence < 1) {
        throw new PkiCryptoException("Invalid LoTE sequence number");
      }
    } else {
      issuedAt = Instant.ofEpochSecond(actual.path("iat").asLong());
      expiresAt = Instant.ofEpochSecond(actual.path("exp").asLong());
    }
    if (issuedAt.isAfter(clock.instant()) || !expiresAt.isAfter(clock.instant())) {
      throw new PkiCryptoException("Document is outside its validity period: " + document.id());
    }
    var expected = ArtifactStore.JSON.readTree(ArtifactStore.JSON.writeValueAsString(
        payload(document, chain.getFirst(), certificates, issuedAt, sequence)));
    if (!expected.equals(actual)) {
      throw new PkiCryptoException(
          "Document differs from its configured contract: " + document.id());
    }
  }

  public static int nextSequence(String previousToken) throws Exception {
    var json = ArtifactStore.JSON.readTree(JWSObject.parse(previousToken).getPayload().toString());
    return Math.addExact(json.path("LoTE").path("ListAndSchemeInformation")
        .path("LoTESequenceNumber").asInt(0), 1);
  }

  private Object payload(Document document, X509Certificate certificate,
      Map<String, X509Certificate> certificates, Instant issuedAt, int sequence) throws Exception {
    Instant expiry = expiry(document, certificate, issuedAt);
    if ("lote".equals(document.type())) {
      var scheme = new LoteDocument.ListAndSchemeInformation(1, sequence,
          "http://uri.etsi.org/19602/LoTEType/wallet-providers",
          List.of(new LoteDocument.LangValue("en", document.schemeOperator())),
          List.of(new LoteDocument.LangValue("en", document.schemeName())), document.territory(),
          issuedAt.toString(), expiry.toString());
      List<LoteDocument.TrustedEntity> entities = new ArrayList<>();
      for (var entity : document.entities()) {
        X509Certificate trusted = certificates.get(entity.reference());
        if (trusted == null) {
          throw new PkiCryptoException("Missing trusted certificate: " + entity.reference());
        }
        String service = switch (entity.role()) {
          case "pid" -> "PID/Issuance";
          case "wallet" -> "WalletSolution/Issuance";
          case "wrpac" -> "WRPAC/Issuance";
          case "wrprc" -> "WRPRC/Issuance";
          default -> throw new PkiCryptoException("Unsupported entity role: " + entity.role());
        };
        var names = List.of(new LoteDocument.LangValue("en", entity.name()));
        var uris = List.of(new LoteDocument.UriValue("en", entity.uri()));
        var information = new LoteDocument.TrustedEntityInformation(names,
            new LoteDocument.TeAddress(List.of(new LoteDocument.PostalAddress("en", entity.name(),
                entity.country())), uris),
            uris);
        var digitalIdentity = new LoteDocument.ServiceDigitalIdentity(List.of(
            new LoteDocument.X509CertificateVal(
                Base64.getEncoder().encodeToString(trusted.getEncoded()))));
        var serviceInformation = new LoteDocument.ServiceInformation(names, digitalIdentity,
            SERVICE_BASE + service, "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
            issuedAt.toString());
        entities.add(new LoteDocument.TrustedEntity(information,
            List.of(new LoteDocument.TrustedEntityService(serviceInformation))));
      }
      return new LoteDocument(new LoteDocument.LoteContent(scheme, entities));
    }
    Map<String, Object> claims = new LinkedHashMap<>(document.claims());
    claims.put("iat", issuedAt.getEpochSecond());
    claims.put("exp", expiry.getEpochSecond());
    if ("status-list".equals(document.type())) {
      String bits = document.statusBits() == null ? EMPTY_STATUS_BITS : document.statusBits();
      validateStatusBits(bits);
      claims.put("iss", document.url());
      claims.put("sub", document.url());
      claims.put("status_list", Map.of("bits", 1, "lst", bits));
    }
    return claims;
  }

  private static Instant expiry(Document document, X509Certificate certificate, Instant issuedAt) {
    Instant expiry = issuedAt.plus(Duration.ofDays(document.validityDays()));
    return expiry.isAfter(certificate.getNotAfter().toInstant())
        ? certificate.getNotAfter().toInstant()
        : expiry;
  }

  private static String type(Document document) {
    return switch (document.type()) {
      case "lote" -> "trustlist+jwt";
      case "status-list" -> "statuslist+jwt";
      default -> "rc-wrp+jwt";
    };
  }

  private static void validateStatusBits(String bits) throws Exception {
    byte[] compressed = Base64.getUrlDecoder().decode(bits);
    try (var inflater = new InflaterInputStream(new ByteArrayInputStream(compressed))) {
      byte[] expanded = inflater.readNBytes(1_048_577);
      if (expanded.length == 0 || expanded.length > 1_048_576) {
        throw new PkiCryptoException("Status list must decompress to 1..1048576 bytes");
      }
    }
  }
}
