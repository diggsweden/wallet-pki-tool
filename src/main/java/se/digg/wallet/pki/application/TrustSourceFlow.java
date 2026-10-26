// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import se.digg.wallet.pki.config.LoteConfig;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.config.TrustSourceConfig;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;
import se.digg.wallet.pki.infrastructure.ArtifactWriter;
import se.digg.wallet.pki.infrastructure.AuthorityStore;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.trustlist.LoteAuthority;
import se.digg.wallet.pki.trustlist.LoteGenerator;
import se.digg.wallet.pki.trustlist.TrustListSigner;
import tools.jackson.databind.json.JsonMapper;

/** A dedicated leaf signs both trust documents; participant CAs are only LoTE entries. */
public final class TrustSourceFlow {
  private static final String STATUS_LIST_PATH = "signed/status-list.jwt";
  private final SecretResolver secrets;
  private final ArtifactWriter writer = new ArtifactWriter();

  public TrustSourceFlow(SecretResolver secrets) {
    this.secrets = secrets;
  }

  public void generate(PkiConfiguration config, PrintWriter out) {
    try (var inputs = loadInputs(config)) {
      var trustedAuthorities = loadTrustedAuthorities(config);
      generate(config, inputs, trustedAuthorities, out);
    }
  }

  public void generateLote(PkiConfiguration config, PrintWriter out) {
    var trustSource = requireSignerConfiguration(config);
    Checks.required(trustSource.lote(), "trustSource.lote");
    var trustedAuthorities = loadTrustedAuthorities(config);
    char[] password = secrets.resolve(trustSource.signer().keystorePassword());
    try {
      var signer = loadExistingSigner(config, password);
      writeLote(config, trustedAuthorities, signer);
      out.println("Generated: lote (existing signer retained)");
    } finally {
      Arrays.fill(password, '\0');
    }
  }

  static TrustSourceConfig requireConfiguration(PkiConfiguration config) {
    var trustSource = requireSignerConfiguration(config);
    Checks.required(trustSource.lote(), "trustSource.lote");
    Checks.text(trustSource.signer().commonName(), "trustSource.signer.commonName");
    Checks.relativePath(trustSource.signer().certificateFile(),
        "trustSource.signer.certificateFile");
    return trustSource;
  }

  ServicePkiInputs loadInputs(PkiConfiguration config) {
    var trustSource = requireConfiguration(config);
    return ServicePkiInputs.load(config, AuthorityRole.TRUST_SOURCE,
        trustSource.signer().keystorePassword(), secrets);
  }

  List<LoteAuthority> loadTrustedAuthorities(PkiConfiguration config) {
    var authorities = new AuthorityStore(config);
    var settings = config.trustSource().lote().trustedAuthorities();
    var entries = new ArrayList<LoteAuthority>();
    loadTrustedAuthorities(entries, authorities, AuthorityRole.WALLET_PROVIDER,
        settings.walletProvider());
    loadTrustedAuthorities(entries, authorities, AuthorityRole.PID_ISSUER, settings.pidIssuer());
    loadTrustedAuthorities(entries, authorities, AuthorityRole.VERIFIER_ACCESS,
        settings.verifierAccess());
    loadTrustedAuthorities(entries, authorities, AuthorityRole.VERIFIER_REGISTRATION,
        settings.verifierRegistration());
    return List.copyOf(entries);
  }

  private void loadTrustedAuthorities(List<LoteAuthority> entries, AuthorityStore authorities,
      AuthorityRole role, List<LoteConfig.Entity> settings) {
    var certificates = new CertificateAuthorityManager();
    for (var entry : settings) {
      var certificate = entry.certificateFile() == null ? authorities.loadPublic(role)
          : certificates.readCertificatePem(Path.of(entry.certificateFile()));
      entries.add(new LoteAuthority(role, certificate, entry));
    }
  }

  void generate(PkiConfiguration config, ServicePkiInputs inputs,
      List<LoteAuthority> trustedAuthorities, PrintWriter out) {
    var signer = generateSigner(config, inputs);
    writeLote(config, trustedAuthorities, signer);
    writeStatusList(config, signer);
    inputs.publishAuthority();
    out.println("Generated: trust-source (new signer; lote and status-list rebuilt)");
  }

  private SigningIdentity generateSigner(PkiConfiguration config, ServicePkiInputs inputs) {
    var settings = config.trustSource().signer();
    var authority = inputs.authority();
    var outputDirectory = Path.of(config.outputDirectory());
    var certificates =
        new CertificateProfileIssuer(new SecureRandom(), config.caDistribution().baseUrl());
    var key = new EcKeyGenerator().generateKeyPair();
    var subject = new CertificateSubject(settings.commonName(), config.organization(),
        SubjectAlternativeNames.empty());
    var certificate =
        certificates.issueTrustSourceSignerCertificate(subject, key.getPublic(), authority);
    var signer = new SigningIdentity(key, certificate);
    new IdentityStores().write(outputDirectory.resolve(settings.keystoreFile()), "trust_source",
        signer, authority, inputs.keystorePassword());
    writer.pem(outputDirectory.resolve(settings.certificateFile()), certificate);
    return signer;
  }

  private void writeLote(PkiConfiguration config, List<LoteAuthority> trustedAuthorities,
      SigningIdentity signer) {
    var lote = config.trustSource().lote();
    var generator = new LoteGenerator();
    var document = generator.buildLoteDocument(trustedAuthorities, lote, config.organization());
    writer.text(Path.of(config.outputDirectory()).resolve(lote.outputFile()),
        generator.sign(document, signer));
  }

  private void writeStatusList(PkiConfiguration config, SigningIdentity signer) {
    var distribution = config.caDistribution();
    String url = distribution.baseUrl().replaceAll("/+$", "") + "/" + STATUS_LIST_PATH;
    Instant issuedAt = Instant.now();
    // The Bash generator's compressed bitset contains 8,192 valid entries.
    String payload = JsonMapper.builder().build().writeValueAsString(Map.of(
        "iss", url, "sub", url, "iat", issuedAt.getEpochSecond(),
        "exp", issuedAt.plus(Duration.ofDays(config.trustSource().lote().validityDays()))
            .getEpochSecond(),
        "status_list", Map.of("bits", 1, "lst", "eJxjYBgFo2AUjFQAAAQAAAE")));
    String token = new TrustListSigner().signJws(payload, signer.keyPair().getPrivate(),
        signer.certificate(), "statuslist+jwt");
    writer.text(Path.of(config.outputDirectory()).resolve(distribution.directory())
        .resolve(STATUS_LIST_PATH), token);
  }

  private SigningIdentity loadExistingSigner(PkiConfiguration config, char[] password) {
    return new IdentityStores().loadTrustSigner(
        Path.of(config.outputDirectory()).resolve(config.trustSource().signer().keystoreFile()),
        password, new AuthorityStore(config).loadPublic(AuthorityRole.TRUST_SOURCE));
  }

  private static TrustSourceConfig requireSignerConfiguration(PkiConfiguration config) {
    var trustSource = Checks.required(config.trustSource(), "trustSource");
    Checks.required(trustSource.signer(), "trustSource.signer");
    return trustSource;
  }
}
