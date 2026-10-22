// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSObject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.TestEnvironment;
import se.digg.wallet.pki.TestEnvironment.Result;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.WalletRole;
import se.digg.wallet.pki.infrastructure.ArtifactLayout;
import se.digg.wallet.pki.storage.ArtifactStore;

class WalletPkiCliComponentTest {
  @TempDir
  Path directory;
  private Path source;

  @BeforeEach
  void setUp() throws Exception {
    source = TestEnvironment.create(directory);
  }

  private Result run(String operation, String... roles) {
    return TestEnvironment.run(new SecretResolver(), TestEnvironment.CLOCK, operation,
        source, roles);
  }

  private Result ensure() {
    var result = run("ensure");
    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    return result;
  }

  private ArtifactLayout layout(Result result) {
    return new ArtifactLayout(directory.resolve("state/generations/" + result.generation()),
        result.bundle());
  }

  @Test
  void configured_roles_create_the_fixed_consumer_keystores() throws Exception {
    var result = ensure();
    var layout = layout(result);
    for (WalletRole role : WalletRole.values()) {
      var store = TestEnvironment.keyStore(layout.keystore(role));
      assertThat(Collections.list(store.aliases())).contains(role.alias());
      assertThat(store.getCertificateChain(role.alias())).hasSize(2);
    }
    assertThat(Collections.list(TestEnvironment.keyStore(layout.pidKeystore()).aliases()))
        .containsExactlyInAnyOrder("pid_issuer", "nonce-encryption", "request-encryption");
    assertThat(run("verify").code()).isZero();
  }

  @Test
  void ensure_reuses_the_generation_without_passwords() throws Exception {
    final var first = ensure();
    Files.delete(directory.resolve("password.txt"));

    var second = run("ensure");

    assertThat(second.code()).withFailMessage(second.errors()).isZero();
    assertThat(second.generation()).isEqualTo(first.generation());
  }

  @Test
  void pid_renewal_preserves_all_three_keys() throws Exception {
    final var first = ensure();
    var before = TestEnvironment.keyStore(layout(first).pidKeystore());

    var second = run("renew", "pid-issuer");

    assertThat(second.code()).withFailMessage(second.errors()).isZero();
    var after = TestEnvironment.keyStore(layout(second).pidKeystore());
    for (String alias : List.of("pid_issuer", "nonce-encryption", "request-encryption")) {
      assertThat(after.getCertificate(alias).getPublicKey())
          .isEqualTo(before.getCertificate(alias).getPublicKey());
      assertThat(after.getCertificate(alias)).isNotEqualTo(before.getCertificate(alias));
    }
  }

  @Test
  void pid_rotation_replaces_all_three_keys() throws Exception {
    final var first = ensure();
    var before = TestEnvironment.keyStore(layout(first).pidKeystore());

    var second = run("rotate", "pid-issuer");

    assertThat(second.code()).withFailMessage(second.errors()).isZero();
    var after = TestEnvironment.keyStore(layout(second).pidKeystore());
    for (String alias : List.of("pid_issuer", "nonce-encryption", "request-encryption")) {
      assertThat(after.getCertificate(alias).getPublicKey())
          .isNotEqualTo(before.getCertificate(alias).getPublicKey());
    }
    var registration = JWSObject.parse(Files.readString(layout(second).pidRegistration()));
    assertThat(registration.getHeader().getX509CertChain().getFirst().decode())
        .isEqualTo(after.getCertificate("pid_issuer").getEncoded());
  }

  @Test
  void participant_rotation_preserves_authorities_and_unrelated_artifacts() throws Exception {
    final var first = ensure();
    var before = layout(first);

    var second = run("rotate", "wallet-provider");

    assertThat(second.code()).withFailMessage(second.errors()).isZero();
    var after = layout(second);
    assertThat(Files.readAllBytes(after.pidKeystore()))
        .isEqualTo(Files.readAllBytes(before.pidKeystore()));
    assertThat(Files.readAllBytes(after.lote())).isEqualTo(Files.readAllBytes(before.lote()));
    assertThat(Files.readAllBytes(after.publication(WalletRole.WALLET_PROVIDER).resolve("ca.pem")))
        .isEqualTo(
            Files.readAllBytes(before.publication(WalletRole.WALLET_PROVIDER).resolve("ca.pem")));
    assertThat(TestEnvironment.keyStore(after.walletKeystore()).getCertificate("wallet_provider")
        .getPublicKey())
        .isNotEqualTo(TestEnvironment.keyStore(before.walletKeystore())
            .getCertificate("wallet_provider").getPublicKey());
  }

  @Test
  void trust_signer_rotation_rebuilds_both_trust_documents() throws Exception {
    final var first = ensure();

    var second = run("rotate", "trust-source");

    assertThat(second.code()).withFailMessage(second.errors()).isZero();
    var layout = layout(second);
    var signer =
        TestEnvironment.keyStore(layout.trustSignerKeystore()).getCertificate("trust_source");
    assertThat(Files.readString(layout.lote()))
        .isNotEqualTo(Files.readString(layout(first).lote()));
    for (Path path : List.of(layout.lote(), layout.statusList())) {
      assertThat(JWSObject.parse(Files.readString(path)).getHeader().getX509CertChain().getFirst()
          .decode()).isEqualTo(signer.getEncoded());
    }
    assertThat(loteSequence(second)).isEqualTo(loteSequence(first) + 1);
  }

  @Test
  void due_documents_are_refreshed_without_reissuing_identity_certificates() throws Exception {
    final var first = ensure();
    Clock later =
        Clock.fixed(TestEnvironment.CLOCK.instant().plus(Duration.ofDays(340)), ZoneOffset.UTC);

    var second = TestEnvironment.run(new SecretResolver(), later, "ensure", source);

    assertThat(second.code()).withFailMessage(second.errors()).isZero();
    for (WalletRole role : WalletRole.values()) {
      assertThat(Files.readAllBytes(layout(second).keystore(role)))
          .isEqualTo(Files.readAllBytes(layout(first).keystore(role)));
    }
    assertThat(loteSequence(second)).isEqualTo(loteSequence(first) + 1);
  }

  @Test
  void missing_secrets_fail_before_creating_private_state() throws Exception {
    Files.delete(directory.resolve("password.txt"));

    var result = run("ensure");

    assertThat(result.code()).isEqualTo(1);
    assertThat(directory.resolve("state")).doesNotExist();
    assertThat(directory.resolve("bundles")).doesNotExist();
  }

  @Test
  void failed_document_generation_preserves_the_current_bundle() throws Exception {
    final var first = ensure();
    Files.writeString(source,
        Files.readString(source).replace("validityDays: 365", "validityDays: 1"));

    var failed = run("ensure");

    assertThat(failed.code()).isEqualTo(1);
    assertThat(directory.resolve("bundles/current").toRealPath()).isEqualTo(first.bundle());
    for (Path parent : List.of(directory.resolve("state/generations"),
        directory.resolve("bundles/generations"))) {
      try (var paths = Files.list(parent)) {
        assertThat(paths.map(p -> p.getFileName().toString()))
            .noneMatch(p -> p.startsWith(".staging-"));
      }
    }
  }

  @Test
  void tampered_files_fail_verification() throws Exception {
    final var first = ensure();
    Files.writeString(layout(first).pidRegistration(), "tampered");

    var result = run("verify");

    assertThat(result.code()).isEqualTo(1);
    assertThat(result.errors()).contains("digest mismatch");
  }

  @Test
  void unmanifested_files_fail_verification() throws Exception {
    final var first = ensure();
    Files.writeString(first.bundle().resolve("public/unexpected.txt"), "extra");

    var result = run("verify");

    assertThat(result.code()).isEqualTo(1);
    assertThat(result.errors()).contains("unmanifested file");
  }

  @Test
  void private_exports_use_owner_only_permissions() throws Exception {
    var result = ensure();

    assertThat(Files.getPosixFilePermissions(layout(result).walletKeystore()))
        .isEqualTo(PosixFilePermissions.fromString("rw-------"));
  }

  @Test
  void rotation_requires_an_explicit_wallet_role() {
    var result = run("rotate");

    assertThat(result.code()).isEqualTo(1);
    assertThat(result.errors()).contains("explicit wallet roles");
    assertThat(directory.resolve("state")).doesNotExist();
  }

  @Test
  void arbitrary_resource_targets_are_rejected() {
    var result = run("ensure", "identity:pid-issuer");

    assertThat(result.code()).isEqualTo(1);
    assertThat(result.errors()).contains("Unknown wallet role");
  }

  @Test
  void supplied_authorities_allow_provisioning_one_wallet_role() throws Exception {
    final var local = ensure();
    var imported = TestEnvironment.importedWalletProvider(directory, source, local.generation());

    var result = TestEnvironment.run(new SecretResolver(), TestEnvironment.CLOCK, "ensure",
        imported, "wallet-provider");

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    assertThat(result.bundle().resolve("private/certificates/wallet-provider/wallet_provider.p12"))
        .exists();
    assertThat(result.bundle().resolve("private/certificates/issuer/pid_issuer.p12"))
        .doesNotExist();
    assertThat(directory.resolve("imported-state/generations/" + result.generation()
        + "/authorities/wallet-provider/ca_private_key.pem")).doesNotExist();
    assertThat(TestEnvironment
        .run(new SecretResolver(), TestEnvironment.CLOCK, "verify", imported).code())
        .isZero();
  }

  @Test
  void imported_trust_anchors_are_pinned_after_first_use() throws Exception {
    final var local = ensure();
    var imported = TestEnvironment.importedWalletProvider(directory, source, local.generation());
    var first =
        TestEnvironment.run(new SecretResolver(), TestEnvironment.CLOCK, "ensure", imported);
    assertThat(first.code()).withFailMessage(first.errors()).isZero();
    var manager = new CertificateAuthorityManager(new EcKeyGenerator(),
        new java.security.SecureRandom(), TestEnvironment.CLOCK);
    manager.saveAuthority(manager.createAuthority("wallet-provider", "Replacement root"),
        directory.resolve("imports"));

    var changed =
        TestEnvironment.run(new SecretResolver(), TestEnvironment.CLOCK, "ensure", imported);

    assertThat(changed.code()).isEqualTo(1);
    assertThat(changed.errors()).contains("Trust anchor changed");
    assertThat(directory.resolve("imported-bundles/current").toRealPath())
        .isEqualTo(first.bundle());
  }

  @Test
  void missing_persistent_managed_keys_are_never_recreated() throws Exception {
    final var local = ensure();
    Files.delete(layout(local).authority(WalletRole.PID_ISSUER).resolve("ca_private_key.pem"));

    var result = run("ensure");

    assertThat(result.code()).isEqualTo(1);
    assertThat(directory.resolve("bundles/current").toRealPath()).isEqualTo(local.bundle());
  }

  @Test
  void selected_roles_do_not_resolve_unrelated_passwords() throws Exception {
    final var local = ensure();
    String yaml = Files.readString(source).replace("file: password.txt", "env: UNAVAILABLE");
    yaml = yaml.replaceFirst("env: UNAVAILABLE", "file: password.txt");
    Files.writeString(source, yaml);

    var result = run("rotate", "pid-issuer");

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    assertThat(Files.readAllBytes(layout(result).walletKeystore()))
        .isEqualTo(Files.readAllBytes(layout(local).walletKeystore()));
  }

  @Test
  void trust_source_uses_only_public_participant_authorities() throws Exception {
    final var local = ensure();
    var imported = TestEnvironment.importedTrustSource(directory, source, local.generation());
    for (WalletRole role : WalletRole.values()) {
      if (role != WalletRole.TRUST_SOURCE) {
        Files.delete(layout(local).authority(role).resolve("ca_private_key.pem"));
      }
    }

    var result =
        TestEnvironment.run(new SecretResolver(), TestEnvironment.CLOCK, "ensure", imported);

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    assertThat(result.bundle().resolve("public/trust-source/signed/trusted-entities.json"))
        .exists();
    assertThat(result.bundle().resolve("private/certificates/issuer/pid_issuer.p12"))
        .doesNotExist();
    assertThat(TestEnvironment
        .run(new SecretResolver(), TestEnvironment.CLOCK, "verify", imported).code())
        .isZero();
  }

  @Test
  void supplied_crls_preserve_revocation_entries_without_reissuing_keys() throws Exception {
    final var local = ensure();
    var imported = TestEnvironment.importedWalletProvider(directory, source, local.generation());
    var first =
        TestEnvironment.run(new SecretResolver(), TestEnvironment.CLOCK, "ensure", imported);
    assertThat(first.code()).withFailMessage(first.errors()).isZero();
    var keys = new EcKeyGenerator();
    var manager = new CertificateAuthorityManager();
    var certificate = manager.readCertificatePem(directory.resolve("imports/ca.pem"));
    var key = keys.readPrivateKeyPem(directory.resolve("imports/ca_private_key.pem"));
    var now = TestEnvironment.CLOCK.instant();
    var builder = new org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder(
        certificate.getSubjectX500Principal(), java.util.Date.from(now.minusSeconds(60)));
    builder.setNextUpdate(java.util.Date.from(now.plus(Duration.ofDays(365))));
    builder.addCRLEntry(java.math.BigInteger.valueOf(123),
        java.util.Date.from(now.minusSeconds(120)), 1);
    var signer =
        new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withECDSA").build(key);
    var crl = new org.bouncycastle.cert.jcajce.JcaX509CRLConverter().getCRL(builder.build(signer));
    keys.writePemFile(crl, directory.resolve("imports/revocation-list.pem"));
    Files.delete(directory.resolve("password.txt"));

    var result =
        TestEnvironment.run(new SecretResolver(), TestEnvironment.CLOCK, "ensure", imported);

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    var published = manager.readCrlPem(
        result.bundle().resolve("public/trust-source/wallet-provider/revocation-list.pem"));
    assertThat(published.getRevokedCertificate(java.math.BigInteger.valueOf(123))).isNotNull();
    String store = "private/certificates/wallet-provider/wallet_provider.p12";
    assertThat(Files.readAllBytes(result.bundle().resolve(store)))
        .isEqualTo(Files.readAllBytes(first.bundle().resolve(store)));
  }

  @Test
  void concurrent_state_writers_are_rejected() throws Exception {
    final var first = ensure();
    var store = new ArtifactStore(new se.digg.wallet.pki.config.ConfigurationLoader().load(source));
    try (var lock = store.lock()) {
      assertThat(lock.lock().isValid()).isTrue();

      var result = run("rotate", "pid-issuer");

      assertThat(result.code()).isEqualTo(1);
      assertThat(directory.resolve("bundles/current").toRealPath()).isEqualTo(first.bundle());
    }
  }

  @Test
  void lost_current_pointers_never_bootstrap_replacement_authorities() throws Exception {
    ensure();
    Files.delete(directory.resolve("bundles/current"));

    var result = run("ensure");

    assertThat(result.code()).isEqualTo(1);
    assertThat(result.errors()).contains("restore the pointer");
  }

  @Test
  void changed_managed_authority_subjects_require_coordinated_rollover() throws Exception {
    final var first = ensure();
    Files.writeString(source,
        Files.readString(source).replace("DIGG Wallet PID Issuer CA", "Replacement PID root"));

    var result = run("ensure");

    assertThat(result.code()).isEqualTo(1);
    assertThat(result.errors()).contains("authority subject changed");
    assertThat(directory.resolve("bundles/current").toRealPath()).isEqualTo(first.bundle());
  }

  @Test
  void verifier_registration_exports_match_the_current_signing_identity() throws Exception {
    final var first = ensure();

    var second = run("rotate", "verifier-registration");

    assertThat(second.code()).withFailMessage(second.errors()).isZero();
    var layout = layout(second);
    var jwt = JWSObject.parse(Files.readString(layout.verifierRegistration()));
    assertThat(jwt.getHeader().getX509CertChain().getFirst().decode())
        .isEqualTo(TestEnvironment.keyStore(layout.verifierRegistrationKeystore())
            .getCertificate("registration").getEncoded());
    assertThat(Files.readString(layout.verifierEnvironment()))
        .isEqualTo("VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE=" + jwt.serialize() + "\n");
    assertThat(Files.readAllBytes(layout.pidKeystore()))
        .isEqualTo(Files.readAllBytes(layout(first).pidKeystore()));
  }

  @Test
  void expired_identity_certificates_are_renewed_without_replacing_keys() throws Exception {
    final var first = ensure();
    Clock later =
        Clock.fixed(TestEnvironment.CLOCK.instant().plus(Duration.ofDays(830)), ZoneOffset.UTC);

    var result = TestEnvironment.run(new SecretResolver(), later, "ensure", source);

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    for (WalletRole role : WalletRole.values()) {
      assertThat(TestEnvironment.keyStore(layout(result).keystore(role))
          .getCertificate(role.alias()).getPublicKey())
          .isEqualTo(TestEnvironment.keyStore(layout(first).keystore(role))
              .getCertificate(role.alias()).getPublicKey());
    }
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(strings = {"alpha", "beta"})
  void managed_single_role_provisioning_is_independent_of_deployment_labels(String label)
      throws Exception {
    var full = new se.digg.wallet.pki.config.ConfigurationLoader().load(source);
    var single = new se.digg.wallet.pki.config.PkiConfiguration(2, label,
        full.stateDirectory(), full.outputDirectory(), full.publicationBaseUrl(),
        full.organization(),
        null, full.walletProvider(), null, null);
    Files.writeString(source, ArtifactStore.JSON.writeValueAsString(single));

    var result = run("ensure");

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    assertThat(layout(result).walletKeystore()).exists();
    assertThat(layout(result).pidKeystore()).doesNotExist();
    assertThat(layout(result).authority(WalletRole.WALLET_PROVIDER).resolve("ca_private_key.pem"))
        .exists();
    assertThat(run("verify").code()).isZero();
  }

  @Test
  void missing_supplied_private_keys_never_create_replacement_authorities() throws Exception {
    var local = ensure();
    var imported = TestEnvironment.importedWalletProvider(directory, source, local.generation());
    Files.delete(directory.resolve("imports/ca_private_key.pem"));

    var result =
        TestEnvironment.run(new SecretResolver(), TestEnvironment.CLOCK, "ensure", imported);

    assertThat(result.code()).isEqualTo(1);
    assertThat(directory.resolve("imported-state")).doesNotExist();
    assertThat(directory.resolve("imported-bundles")).doesNotExist();
  }

  @Test
  void legacy_manifest_metadata_preserves_the_committed_generation() throws Exception {
    var first = ensure();
    var manifest = (tools.jackson.databind.node.ObjectNode) ArtifactStore.JSON.readTree(
        Files.readString(first.bundle().resolve("manifest.json")));
    manifest.put("workflow", "legacy-mode");
    String contents = ArtifactStore.JSON.writeValueAsString(manifest);
    Files.writeString(first.bundle().resolve("manifest.json"), contents);
    Files.writeString(layout(first).state().resolve("manifest.json"), contents);

    var result = run("ensure");

    assertThat(result.code()).withFailMessage(result.errors()).isZero();
    assertThat(result.generation()).isEqualTo(first.generation());
    assertThat(run("verify").code()).isZero();
  }

  @Test
  void help_exposes_wallet_operations_directly() {
    var output = new java.io.StringWriter();
    var cli = new WalletPkiCli(new java.io.PrintWriter(output),
        new java.io.PrintWriter(new java.io.StringWriter()));

    int result = cli.execute("--help");

    assertThat(result).isZero();
    assertThat(output.toString()).contains("ensure", "renew", "rotate", "verify");
  }

  private int loteSequence(Result result) throws Exception {
    return ArtifactStore.JSON
        .readTree(JWSObject.parse(Files.readString(layout(result).lote())).getPayload().toString())
        .path("LoTE").path("ListAndSchemeInformation").path("LoTESequenceNumber").asInt();
  }
}
