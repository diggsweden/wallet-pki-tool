// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.config.TrustSourceConfig;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.domain.CertificateSubject;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.SubjectAlternativeNames;
import se.digg.wallet.pki.domain.WalletTrustAnchors;
import se.digg.wallet.pki.infrastructure.ArtifactWriter;
import se.digg.wallet.pki.infrastructure.AuthorityStore;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.trustlist.LoteGenerator;
import se.digg.wallet.pki.trustlist.StatusListGenerator;

/** A dedicated leaf signs both trust documents; participant CAs are only LoTE entries. */
public final class TrustSourceFlow {
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

  public void generateStatusList(PkiConfiguration config, PrintWriter out) {
    var trustSource = requireSignerConfiguration(config);
    Checks.required(trustSource.statusList(), "trustSource.statusList");
    char[] password = secrets.resolve(trustSource.signer().keystorePassword());
    try {
      var signer = loadExistingSigner(config, password);
      writeStatusList(config, signer);
      out.println("Generated: status-list (existing signer retained)");
    } finally {
      Arrays.fill(password, '\0');
    }
  }

  static TrustSourceConfig requireConfiguration(PkiConfiguration config) {
    var trustSource = requireSignerConfiguration(config);
    Checks.required(trustSource.lote(), "trustSource.lote");
    Checks.required(trustSource.statusList(), "trustSource.statusList");
    Checks.text(trustSource.signer().commonName(), "trustSource.signer.commonName");
    Checks.relativePath(trustSource.signer().certificateFile(), "trustSource.signer.certificateFile");
    return trustSource;
  }

  ServicePkiInputs loadInputs(PkiConfiguration config) {
    var trustSource = requireConfiguration(config);
    return ServicePkiInputs.load(config, AuthorityRole.TRUST_SOURCE,
        trustSource.signer().keystorePassword(), secrets);
  }

  WalletTrustAnchors loadTrustedAuthorities(PkiConfiguration config) {
    var authorities = new AuthorityStore(config);
    return new WalletTrustAnchors(authorities.loadPublic(AuthorityRole.PID_ISSUER),
        authorities.loadPublic(AuthorityRole.WALLET_PROVIDER),
        authorities.loadPublic(AuthorityRole.VERIFIER_ACCESS),
        authorities.loadPublic(AuthorityRole.VERIFIER_REGISTRATION));
  }

  void generate(PkiConfiguration config, ServicePkiInputs inputs,
      WalletTrustAnchors trustedAuthorities, PrintWriter out) {
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
        new CertificateProfileIssuer(new SecureRandom(), config.publication().baseUrl());
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

  private void writeLote(PkiConfiguration config, WalletTrustAnchors trustedAuthorities,
      SigningIdentity signer) {
    var lote = config.trustSource().lote();
    var generator = new LoteGenerator();
    var document = generator.buildLoteDocument(trustedAuthorities, lote, config.organization());
    writer.text(Path.of(config.outputDirectory()).resolve(lote.outputFile()),
        generator.sign(document, signer));
  }

  private void writeStatusList(PkiConfiguration config, SigningIdentity signer) {
    var statusList = config.trustSource().statusList();
    var token = new StatusListGenerator().buildAndSignStatusList(statusList.url(),
        StatusListGenerator.DEFAULT_EMPTY_STATUS_LIST, signer.keyPair().getPrivate(),
        signer.certificate(), Instant.now(), Duration.ofDays(statusList.validityDays()));
    writer.text(Path.of(config.outputDirectory()).resolve(statusList.outputFile()), token);
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
