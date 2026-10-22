// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.TestEnvironment;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.generator.PkiEngine;
import se.digg.wallet.pki.storage.ArtifactStore;

class WalletPkiCliComponentTest {
  private static final String REGISTRATION_STORE =
      "private/certificates/verifier-registration-certificate/"
          + "verifier-registration-certificate.p12";
  @TempDir
  Path directory;
  private Path configuration;
  private WalletPkiCli cli;
  private StringWriter output;
  private StringWriter errors;

  @BeforeEach
  void setUp() throws Exception {
    configuration = TestEnvironment.create(directory);
    output = new StringWriter();
    errors = new StringWriter();
    cli = new WalletPkiCli(new PkiEngine(new SecretResolver(), TestEnvironment.CLOCK),
        new PrintWriter(output), new PrintWriter(errors));
  }

  @Test
  void planning_requires_no_secrets_or_output_directories() throws Exception {
    Files.delete(directory.resolve("password.txt"));

    int result = run("plan");

    assertThat(result).isZero();
    assertThat(output.toString()).contains("CREATE authority:pid-issuer", "Required secrets:");
    assertThat(directory.resolve("state")).doesNotExist();
    assertThat(directory.resolve("bundles")).doesNotExist();
  }

  @Test
  void saved_plans_can_be_applied_through_the_cli() throws Exception {
    assertThat(run("plan", "--json")).isZero();
    Path saved = directory.resolve("plan.json");
    Files.writeString(saved, output.toString());
    output.getBuffer().setLength(0);

    int result = run("apply", "--plan", saved.toString());

    assertThat(result).withFailMessage(errors.toString()).isZero();
    assertThat(bundle().resolve("manifest.json")).exists();
    assertThat(run("verify")).withFailMessage(errors.toString()).isZero();
  }

  @Test
  void generated_keystores_preserve_the_ecosystem_alias_contract() throws Exception {
    int result = run("ensure");

    assertThat(result).withFailMessage(errors.toString()).isZero();
    Path bundle = bundle();
    var pid =
        TestEnvironment.keyStore(bundle.resolve("private/certificates/issuer/pid_issuer.p12"));
    assertThat(Collections.list(pid.aliases()))
        .containsExactlyInAnyOrder("pid_issuer", "nonce-encryption", "request-encryption");
    var verifier = TestEnvironment.keyStore(bundle.resolve(
        "private/certificates/verifier-access-certificate/verifier-access-certificate.p12"));
    assertThat(Collections.list(verifier.aliases())).containsExactly("verifier_access_certificate");
    var registration = TestEnvironment.keyStore(bundle.resolve(
        REGISTRATION_STORE));
    assertThat(Collections.list(registration.aliases())).containsExactly("registration");
    var trust =
        TestEnvironment.keyStore(bundle.resolve("private/certificates/trusted_issuers.p12"));
    assertThat(Collections.list(trust.aliases())).containsExactlyInAnyOrder("pid_issuer",
        "pid_issuer_ca");
    assertThat(run("verify")).withFailMessage(errors.toString()).isZero();
  }

  @Test
  @SuppressWarnings("PMD.AvoidUsingHardCodedIP") // Documentation address tests IPv6 SAN encoding.
  void ipv6_subject_alternative_names_are_encoded_as_addresses() throws Exception {
    Files.writeString(configuration, Files.readString(configuration)
        .replace("IP:10.0.2.2", "IP:2001:db8::1"));

    assertThat(run("ensure")).withFailMessage(errors.toString()).isZero();

    var pid = TestEnvironment.keyStore(
        bundle().resolve("private/certificates/issuer/pid_issuer.p12"));
    var certificate = (X509Certificate) pid.getCertificate("pid_issuer");
    assertThat(certificate.getSubjectAlternativeNames())
        .contains(List.of(7, "2001:db8:0:0:0:0:0:1"));
  }

  @Test
  void signed_documents_never_outlive_the_signing_certificate() throws Exception {
    Files.writeString(configuration, Files.readString(configuration)
        .replace("validityDays: 365", "validityDays: 1000"));

    assertThat(run("ensure")).withFailMessage(errors.toString()).isZero();

    var signer = TestEnvironment.keyStore(
        bundle().resolve("private/certificates/trust-list-signer/trust_source.p12"));
    var certificate = (X509Certificate) signer.getCertificate("trust_source");
    var jwt = JWSObject.parse(Files.readString(
        bundle().resolve("public/trust-source/signed/status-list.jwt")));
    assertThat(ArtifactStore.JSON.readTree(jwt.getPayload().toString()).path("exp").asLong())
        .isEqualTo(certificate.getNotAfter().toInstant().getEpochSecond());
  }

  @Test
  void registration_tokens_match_the_exported_signing_identity() throws Exception {
    assertThat(run("ensure")).withFailMessage(errors.toString()).isZero();
    Path bundle = bundle();
    var registration = TestEnvironment.keyStore(bundle.resolve(
        REGISTRATION_STORE));

    String token = Files.readString(bundle.resolve(
        "public/certificates/verifier-registration-certificate/registration_certificate.jwt"));
    JWSObject jwt = JWSObject.parse(token);

    assertThat(jwt.getHeader().getType().toString()).isEqualTo("rc-wrp+jwt");
    assertThat(jwt.getHeader().getX509CertChain()).hasSize(2);
    assertThat(jwt.getHeader().getX509CertChain().getFirst().decode())
        .isEqualTo(registration.getCertificate("registration").getEncoded());
    assertThat(jwt.verify(new ECDSAVerifier(
        (ECPublicKey) registration.getCertificate("registration").getPublicKey()))).isTrue();
    assertThat(Files.readString(bundle.resolve(
        "public/certificates/verifier-registration-certificate/registration_certificate.env")))
        .isEqualTo("VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE=" + token + "\n");
    assertThat(ArtifactStore.JSON.readTree(jwt.getPayload().toString())
        .path("credentials").get(0).path("claim")).hasSize(8);
  }

  @Test
  void trust_lists_use_the_dedicated_signer_and_explicit_entity_roles() throws Exception {
    assertThat(run("ensure")).withFailMessage(errors.toString()).isZero();
    Path bundle = bundle();
    var signer = TestEnvironment.keyStore(bundle.resolve(
        "private/certificates/trust-list-signer/trust_source.p12"));

    var jwt = JWSObject.parse(
        Files.readString(bundle.resolve("public/trust-source/signed/trusted-entities.json")));

    assertThat(jwt.getHeader().getX509CertChain().getFirst().decode())
        .isEqualTo(signer.getCertificate("trust_source").getEncoded());
    assertThat(jwt.verify(
        new ECDSAVerifier((ECPublicKey) signer.getCertificate("trust_source").getPublicKey())))
        .isTrue();
    var entities = ArtifactStore.JSON.readTree(jwt.getPayload().toString())
        .path("LoTE").path("TrustedEntitiesList");
    assertThat(entities).hasSize(4);
    assertThat(entities.get(1).path("TrustedEntityServices").get(0).path("ServiceInformation")
        .path("ServiceTypeIdentifier").asText()).endsWith("WalletSolution/Issuance");
    assertThat(entities.get(0).path("TrustedEntityServices").get(0).path("ServiceInformation")
        .path("ServiceTypeIdentifier").asText()).endsWith("PID/Issuance");
  }

  @Test
  void ensure_reuses_the_committed_generation_without_secrets() throws Exception {
    assertThat(run("ensure")).withFailMessage(errors.toString()).isZero();
    Path previous = bundle();
    Files.delete(directory.resolve("password.txt"));

    int result = run("ensure");

    assertThat(result).withFailMessage(errors.toString()).isZero();
    assertThat(bundle()).isEqualTo(previous);
  }

  @Test
  void rotating_registration_preserves_unrelated_keys_and_trust_lists() throws Exception {
    assertThat(run("ensure")).withFailMessage(errors.toString()).isZero();
    Path previous = bundle();
    String leaf =
        REGISTRATION_STORE;
    byte[] priorKey = TestEnvironment.keyStore(previous.resolve(leaf))
        .getCertificate("registration").getPublicKey().getEncoded();

    int result = run("rotate", "identity:verifier-registration-certificate");

    assertThat(result).withFailMessage(errors.toString()).isZero();
    assertThat(TestEnvironment.keyStore(bundle().resolve(leaf)).getCertificate("registration")
        .getPublicKey().getEncoded()).isNotEqualTo(priorKey);
    for (String path : List.of("private/certificates/issuer/pid_issuer.p12",
        "public/trust-source/signed/trusted-entities.json",
        "public/trust-source/signed/status-list.jwt")) {
      assertThat(Files.readAllBytes(bundle().resolve(path)))
          .isEqualTo(Files.readAllBytes(previous.resolve(path)));
    }
    assertThat(Files.readString(bundle().resolve(
        "public/certificates/verifier-registration-certificate/registration_certificate.jwt")))
        .isNotEqualTo(Files.readString(previous.resolve(
            "public/certificates/verifier-registration-certificate/registration_certificate.jwt")));
  }

  @Test
  void renewal_preserves_every_pid_key() throws Exception {
    assertThat(run("ensure")).withFailMessage(errors.toString()).isZero();
    Path previous = bundle();
    String path = "private/certificates/issuer/pid_issuer.p12";
    var before = TestEnvironment.keyStore(previous.resolve(path));

    int result = run("renew", "identity:pid-issuer");

    assertThat(result).withFailMessage(errors.toString()).isZero();
    var after = TestEnvironment.keyStore(bundle().resolve(path));
    for (String alias : Collections.list(before.aliases())) {
      assertThat(after.getCertificate(alias).getPublicKey())
          .isEqualTo(before.getCertificate(alias).getPublicKey());
      assertThat(after.getCertificate(alias)).isNotEqualTo(before.getCertificate(alias));
    }
    assertThat(Files.readString(bundle().resolve("public/pid-issuer/issuer_wrprc.jwt")))
        .isNotEqualTo(Files.readString(previous.resolve("public/pid-issuer/issuer_wrprc.jwt")));
  }

  @Test
  void missing_secrets_leave_no_generated_state() throws Exception {
    Files.delete(directory.resolve("password.txt"));

    int result = run("ensure");

    assertThat(result).isEqualTo(1);
    assertThat(directory.resolve("state")).doesNotExist();
    assertThat(directory.resolve("bundles")).doesNotExist();
    assertThat(errors.toString()).contains("Cannot read password file");
  }

  @Test
  void failed_document_generation_preserves_the_previous_bundle() throws Exception {
    assertThat(run("ensure")).withFailMessage(errors.toString()).isZero();
    Path previous = bundle();
    Files.writeString(configuration, Files.readString(configuration)
        .replace("type: status-list", "type: status-list\n    statusBits: invalid"));

    int result = run("ensure");

    assertThat(result).isEqualTo(1);
    assertThat(bundle()).isEqualTo(previous);
    try (var files = Files.list(directory.resolve("state/generations"))) {
      assertThat(files.map(p -> p.getFileName().toString()).toList()).hasSize(1);
    }
  }

  @Test
  void altered_exports_fail_verification() throws Exception {
    assertThat(run("ensure")).withFailMessage(errors.toString()).isZero();
    Files.writeString(bundle().resolve("public/trust-source/signed/status-list.jwt"), "altered");

    int result = run("verify");

    assertThat(result).isEqualTo(1);
    assertThat(errors.toString()).contains("Artifact digest mismatch");
  }

  @Test
  void missing_managed_authorities_are_never_replaced_implicitly() throws Exception {
    Files.writeString(configuration,
        Files.readString(configuration).replace("create: true", "create: false"));

    int result = run("ensure");

    assertThat(result).isEqualTo(1);
    assertThat(errors.toString()).contains("Missing persistent authority");
    assertThat(directory.resolve("state")).doesNotExist();
  }

  @Test
  void machine_reports_do_not_expose_password_values() throws Exception {
    int result = run("ensure", "--json");

    assertThat(result).withFailMessage(errors.toString()).isZero();
    var report = ArtifactStore.JSON.readTree(output.toString());
    assertThat(report.path("generation").asText()).isNotBlank();
    assertThat(output.toString()).doesNotContain(TestEnvironment.PASSWORD, "PRIVATE KEY");
  }

  @Test
  void private_exports_are_owner_readable_only() throws Exception {
    assertThat(run("ensure")).withFailMessage(errors.toString()).isZero();
    Path path = bundle().resolve("private/certificates/issuer/pid_issuer.p12");

    if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      assertThat(java.nio.file.attribute.PosixFilePermissions
          .toString(Files.getPosixFilePermissions(path)))
          .isEqualTo("rw-------");
    }
    assertThat(path.resolveSibling("pid_issuer.p12.license")).exists();
  }

  private int run(String operation, String... args) {
    List<String> arguments =
        new java.util.ArrayList<>(List.of(operation, "--config", configuration.toString()));
    arguments.addAll(List.of(args));
    return cli.execute(arguments.toArray(String[]::new));
  }

  private Path bundle() throws Exception {
    Path pointer = directory.resolve("bundles/current");
    return pointer.getParent().resolve(Files.readSymbolicLink(pointer));
  }
}
