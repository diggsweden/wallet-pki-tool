// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.TestEnvironment;
import se.digg.wallet.pki.TestEnvironment.Result;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.WalletRole;
import se.digg.wallet.pki.infrastructure.ArtifactLayout;

class WalletPkiCliComponentTest {
  @TempDir
  Path directory;
  private Path source;

  @BeforeEach
  void setUp() throws Exception {
    source = TestEnvironment.create(directory);
  }

  private void initialize() {
    var result = TestEnvironment.run("init-authorities", source);
    assertThat(result.code()).withFailMessage(result.errors()).isZero();
  }

  private Result generate(String... args) {
    var result = TestEnvironment.run("generate", source, args);
    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    return result;
  }

  @Test
  void generation_requires_explicit_authority_initialization() {
    var result = TestEnvironment.run("generate", source);

    assertThat(result.code()).isEqualTo(1);
    assertThat(result.errors()).contains("init-authorities");
    assertThat(directory.resolve("authorities")).doesNotExist();
    assertThat(directory.resolve("generated")).doesNotExist();
  }

  @Test
  void authority_initialization_needs_no_keystore_passwords() throws Exception {
    Files.delete(directory.resolve("password.txt"));

    var result = TestEnvironment.run("init-authorities", source);

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    assertThat(directory.resolve("authorities/pid-issuer/ca_private_key.pem")).exists();
    assertThat(directory.resolve("generated")).doesNotExist();
  }

  @Test
  void repeated_initialization_preserves_all_authority_files() throws Exception {
    initialize();
    Path root = directory.resolve("authorities/pid-issuer");
    byte[] key = Files.readAllBytes(root.resolve("ca_private_key.pem"));
    final byte[] certificate = Files.readAllBytes(root.resolve("ca.pem"));
    final byte[] crl = Files.readAllBytes(root.resolve("revocation-list.pem"));

    initialize();

    assertThat(Files.readAllBytes(root.resolve("ca_private_key.pem"))).isEqualTo(key);
    assertThat(Files.readAllBytes(root.resolve("ca.pem"))).isEqualTo(certificate);
    assertThat(Files.readAllBytes(root.resolve("revocation-list.pem"))).isEqualTo(crl);
  }

  @Test
  void incomplete_managed_authorities_are_never_replaced() throws Exception {
    initialize();
    Path root = directory.resolve("authorities/pid-issuer");
    final byte[] certificate = Files.readAllBytes(root.resolve("ca.pem"));
    Files.delete(root.resolve("ca_private_key.pem"));

    var result = TestEnvironment.run("init-authorities", source);

    assertThat(result.code()).isEqualTo(1);
    assertThat(root.resolve("ca_private_key.pem")).doesNotExist();
    assertThat(Files.readAllBytes(root.resolve("ca.pem"))).isEqualTo(certificate);
  }

  @Test
  void generation_produces_the_fixed_consumer_keystores() throws Exception {
    initialize();

    var result = generate();

    var layout = new ArtifactLayout(result.directory());
    for (WalletRole role : WalletRole.values()) {
      var store = TestEnvironment.keyStore(layout.keystore(role));
      assertThat(Collections.list(store.aliases())).contains(role.alias());
      assertThat(store.getCertificateChain(role.alias())).hasSize(2);
    }
    assertThat(Collections.list(TestEnvironment.keyStore(layout.pidKeystore()).aliases()))
        .containsExactlyInAnyOrder("pid_issuer", "nonce-encryption", "request-encryption");
    assertThat(result.directory().resolve("manifest.json")).doesNotExist();
  }

  @Test
  void each_generation_creates_fresh_participant_keys_and_preserves_the_ca() throws Exception {
    initialize();
    var first = generate();
    var before = new ArtifactLayout(first.directory());
    byte[] ca = Files.readAllBytes(directory.resolve("authorities/pid-issuer/ca.pem"));

    var second = generate("--output", directory.resolve("another-output").toString());

    var after = new ArtifactLayout(second.directory());
    for (String alias : List.of("pid_issuer", "nonce-encryption", "request-encryption")) {
      assertThat(TestEnvironment.keyStore(after.pidKeystore()).getCertificate(alias).getPublicKey())
          .isNotEqualTo(
              TestEnvironment.keyStore(before.pidKeystore()).getCertificate(alias).getPublicKey());
    }
    assertThat(Files.readAllBytes(after.publication(WalletRole.PID_ISSUER).resolve("ca.pem")))
        .isEqualTo(ca);
    assertThat(Files.readAllBytes(directory.resolve("authorities/pid-issuer/ca.pem")))
        .isEqualTo(ca);
  }

  @Test
  void existing_output_directories_are_never_overwritten() throws Exception {
    initialize();
    var first = generate();
    Path keystore = new ArtifactLayout(first.directory()).pidKeystore();
    byte[] before = Files.readAllBytes(keystore);

    var result = TestEnvironment.run("generate", source);

    assertThat(result.code()).isEqualTo(1);
    assertThat(result.errors()).contains("Output already exists");
    assertThat(Files.readAllBytes(keystore)).isEqualTo(before);
  }

  @Test
  void even_empty_output_directories_require_an_explicit_fresh_destination() throws Exception {
    initialize();
    Files.createDirectory(directory.resolve("generated"));

    var result = TestEnvironment.run("generate", source);

    assertThat(result.code()).isEqualTo(1);
    assertThat(result.errors()).contains("fresh directory");
  }

  @Test
  void pid_registration_is_signed_by_the_exported_pid_key() throws Exception {
    initialize();
    var result = generate("pid-issuer");
    var layout = new ArtifactLayout(result.directory());
    var store = TestEnvironment.keyStore(layout.pidKeystore());

    var jwt = JWSObject.parse(Files.readString(layout.pidRegistration()));

    assertThat(jwt.verify(new ECDSAVerifier(
        (java.security.interfaces.ECPublicKey) store.getCertificate("pid_issuer").getPublicKey())))
        .isTrue();
    assertThat(jwt.getHeader().getX509CertChain().getFirst().decode())
        .isEqualTo(store.getCertificate("pid_issuer").getEncoded());
    assertThat(result.directory().resolve("private/certificates/wallet-provider")).doesNotExist();
  }

  @Test
  void verifier_registration_exports_the_same_signed_token_to_the_environment_file()
      throws Exception {
    initialize();
    var result = generate("verifier-registration");
    var layout = new ArtifactLayout(result.directory());

    var jwt = JWSObject.parse(Files.readString(layout.verifierRegistration()));

    assertThat(Files.readString(layout.verifierEnvironment()))
        .isEqualTo("VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE=" + jwt.serialize() + "\n");
    assertThat(jwt.getHeader().getX509CertChain()).hasSize(2);
    assertThat(jwt.getHeader().getX509CertChain().getFirst().decode())
        .isEqualTo(TestEnvironment.keyStore(layout.verifierRegistrationKeystore())
            .getCertificate("registration").getEncoded());
  }

  @Test
  void trust_documents_use_the_dedicated_signer_and_configured_sequence() throws Exception {
    initialize();
    Files.writeString(source,
        Files.readString(source).replace("sequenceNumber: 1", "sequenceNumber: 7"));

    var result = generate("trust-source");

    var layout = new ArtifactLayout(result.directory());
    var certificate =
        TestEnvironment.keyStore(layout.trustSignerKeystore()).getCertificate("trust_source");
    for (Path path : List.of(layout.lote(), layout.statusList())) {
      var jwt = JWSObject.parse(Files.readString(path));
      assertThat(jwt.verify(
          new ECDSAVerifier((java.security.interfaces.ECPublicKey) certificate.getPublicKey())))
          .isTrue();
      assertThat(jwt.getHeader().getX509CertChain().getFirst().decode())
          .isEqualTo(certificate.getEncoded());
    }
    var payload = TestEnvironment.JSON
        .readTree(JWSObject.parse(Files.readString(layout.lote())).getPayload().toString());
    assertThat(
        payload.path("LoTE").path("ListAndSchemeInformation").path("LoTESequenceNumber").asInt())
        .isEqualTo(7);
    assertThat(payload.path("LoTE").path("TrustedEntitiesList")).hasSize(4);
  }

  @Test
  void selected_roles_do_not_resolve_unrelated_passwords() throws Exception {
    initialize();
    String yaml = Files.readString(source).replace("file: password.txt", "env: UNAVAILABLE");
    Files.writeString(source, yaml.replaceFirst("env: UNAVAILABLE", "file: password.txt"));

    var result = TestEnvironment.run("generate", source, "pid-issuer");

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
  }

  @Test
  void missing_passwords_do_not_publish_an_output_directory() throws Exception {
    initialize();
    Files.delete(directory.resolve("password.txt"));

    var result = TestEnvironment.run("generate", source);

    assertThat(result.code()).isEqualTo(1);
    assertThat(directory.resolve("generated")).doesNotExist();
    try (var entries = Files.list(directory)) {
      assertThat(entries.map(p -> p.getFileName().toString()))
          .noneMatch(name -> name.startsWith(".wallet-pki-"));
    }
  }

  @Test
  void private_outputs_are_readable_only_by_the_owner() throws Exception {
    initialize();
    var result = generate();

    assertThat(
        Files.getPosixFilePermissions(new ArtifactLayout(result.directory()).walletKeystore()))
        .isEqualTo(PosixFilePermissions.fromString("rw-------"));
  }

  @Test
  void supplied_authorities_allow_independent_wallet_provider_generation() throws Exception {
    initialize();
    final var supplied = TestEnvironment.importedWalletProvider(directory, source);

    var result = TestEnvironment.run("generate", supplied);

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    var layout = new ArtifactLayout(result.directory());
    assertThat(layout.walletKeystore()).exists();
    assertThat(layout.pidKeystore()).doesNotExist();
    assertThat(Files.readAllBytes(layout.publication(WalletRole.WALLET_PROVIDER).resolve("ca.pem")))
        .isEqualTo(Files.readAllBytes(directory.resolve("inputs/ca.pem")));
    try (var files = Files.walk(result.directory())) {
      assertThat(files.map(p -> p.getFileName().toString())).doesNotContain("ca_private_key.pem");
    }
  }

  @Test
  void supplied_revocation_entries_are_published_unchanged() throws Exception {
    initialize();
    final var supplied = TestEnvironment.importedWalletProvider(directory, source);
    var keys = new EcKeyGenerator();
    var manager = new CertificateAuthorityManager();
    var certificate = manager.readCertificatePem(directory.resolve("inputs/ca.pem"));
    var key = keys.readPrivateKeyPem(directory.resolve("inputs/ca_private_key.pem"));
    var now = TestEnvironment.CLOCK.instant();
    var builder = new org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder(
        certificate.getSubjectX500Principal(), java.util.Date.from(now.minusSeconds(60)));
    builder.setNextUpdate(java.util.Date.from(now.plus(java.time.Duration.ofDays(365))));
    builder.addCRLEntry(java.math.BigInteger.valueOf(123),
        java.util.Date.from(now.minusSeconds(120)), 1);
    var signer =
        new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA").build(key);
    var crl = new org.bouncycastle.cert.jcajce.JcaX509CRLConverter().getCRL(builder.build(signer));
    keys.writePemFile(crl, directory.resolve("inputs/revocation-list.pem"));

    var result = TestEnvironment.run("generate", supplied);

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    var published = manager.readCrlPem(new ArtifactLayout(result.directory())
        .publication(WalletRole.WALLET_PROVIDER).resolve("revocation-list.pem"));
    assertThat(published.getEncoded()).isEqualTo(crl.getEncoded());
    assertThat(published.getRevokedCertificate(java.math.BigInteger.valueOf(123))).isNotNull();
  }

  @Test
  void missing_supplied_private_keys_fail_without_initializing_new_roots() throws Exception {
    initialize();
    final var supplied = TestEnvironment.importedWalletProvider(directory, source);
    Files.delete(directory.resolve("inputs/ca_private_key.pem"));

    var result = TestEnvironment.run("generate", supplied);

    assertThat(result.code()).isEqualTo(1);
    assertThat(directory.resolve("unused-authorities")).doesNotExist();
    assertThat(directory.resolve("imported-output")).doesNotExist();
  }

  @Test
  void trust_source_generation_needs_only_public_participant_authorities() throws Exception {
    initialize();
    final var supplied = TestEnvironment.importedTrustSource(directory, source);
    for (WalletRole role : WalletRole.values()) {
      if (role != WalletRole.TRUST_SOURCE) {
        Files.delete(directory.resolve("authorities/" + role.directory() + "/ca_private_key.pem"));
      }
    }

    var result = TestEnvironment.run("generate", supplied);

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    assertThat(new ArtifactLayout(result.directory()).lote()).exists();
    assertThat(new ArtifactLayout(result.directory()).pidKeystore()).doesNotExist();
  }

  @Test
  void short_lived_documents_are_generated_without_renewal_policy() throws Exception {
    initialize();
    Files.writeString(source,
        Files.readString(source).replace("validityDays: 365", "validityDays: 1"));

    var result = TestEnvironment.run("generate", source);

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
  }

  @Test
  void any_subset_of_managed_roles_can_be_initialized_and_generated() throws Exception {
    var full = new ConfigurationLoader().load(source);
    var single = new PkiConfiguration(full.authorityDirectory(), full.outputDirectory(),
        full.publicationBaseUrl(), full.organization(), null, full.walletProvider(), null, null);
    TestEnvironment.save(source, single);

    initialize();
    var result = generate();

    assertThat(new ArtifactLayout(result.directory()).walletKeystore()).exists();
    assertThat(directory.resolve("authorities/pid-issuer")).doesNotExist();
  }

  @Test
  void output_overrides_cannot_overlap_managed_authorities() {
    initialize();

    var result = TestEnvironment.run("generate", source, "--output",
        directory.resolve("authorities/nested").toString());

    assertThat(result.code()).isEqualTo(1);
    assertThat(result.errors()).contains("separate and non-nested");
  }

  @Test
  void unknown_roles_fail_before_authority_initialization() {
    var result = TestEnvironment.run("init-authorities", source, "identity:pid-issuer");

    assertThat(result.code()).isEqualTo(1);
    assertThat(directory.resolve("authorities")).doesNotExist();
  }

  @Test
  void help_exposes_initialization_and_generation() {
    var output = new java.io.StringWriter();
    var cli = new WalletPkiCli(new java.io.PrintWriter(output),
        new java.io.PrintWriter(new java.io.StringWriter()));

    int result = cli.execute("--help");

    assertThat(result).isZero();
    assertThat(output.toString()).contains("init-authorities", "generate");
  }
}
