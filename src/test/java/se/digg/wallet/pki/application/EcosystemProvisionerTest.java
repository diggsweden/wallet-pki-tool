// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import com.nimbusds.jose.JWSObject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.KeystoreManager;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.infrastructure.AuthorityStore;
import se.digg.wallet.pki.support.EcosystemFixture;
import se.digg.wallet.pki.trustlist.TrustListSigner;
import tools.jackson.databind.json.JsonMapper;

class EcosystemProvisionerTest {
  @TempDir
  Path directory;

  @Test
  void full_generation_produces_the_consumer_keystores_and_signed_documents() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var provisioner = EcosystemFixture.provisioner();
    provisioner.initializeAuthorities(config, EcosystemFixture.quiet());
    provisioner.generate(config, List.of(), EcosystemFixture.quiet());
    var outputDirectory = Path.of(config.outputDirectory());
    for (String relative : List.of("certificates/issuer/pid_issuer.p12",
        "certificates/wallet-provider/wallet_provider.p12",
        "certificates/verifier-access-certificate/verifier-access-certificate.p12",
        "certificates/verifier-registration-certificate/verifier-registration-certificate.p12",
        "certificates/trust-list-signer/trust_source.p12", "pid-issuer/issuer_wrprc.jwt",
        "certificates/verifier-registration-certificate/registration_certificate.env",
        "trust-source/signed/trusted-entities.json", "trust-source/signed/status-list.jwt")) {
      assertThat(Files.isRegularFile(Path.of(config.outputDirectory()).resolve(relative)))
          .as(relative).isTrue();
    }
    var authorities = new AuthorityStore(config);
    KeyStore pid = load(directory.resolve("config/certificates/issuer/pid_issuer.p12"));
    assertThat(java.util.Collections.list(pid.aliases())).containsExactlyInAnyOrder("pid_issuer",
        "nonce-encryption", "request-encryption");
    for (String alias : List.of("pid_issuer", "nonce-encryption", "request-encryption")) {
      assertThat(pid.getCertificateChain(alias)).hasSize(2);
      assertThat(pid.getCertificateChain(alias)[1])
          .isEqualTo(authorities.loadPublic(AuthorityRole.PID_ISSUER));
      assertThat(pid.getKey(alias, "test-password".toCharArray())).isNotNull();
    }
    assertThat(java.util.Collections
        .list(load(directory.resolve("config/certificates/wallet-provider/wallet_provider.p12")).aliases()))
        .containsExactly("wallet_provider");
    assertThat(java.util.Collections
        .list(load(directory.resolve("config/certificates/verifier-access-certificate/verifier-access-certificate.p12")).aliases()))
        .containsExactly("verifier_access_certificate");
    assertThat(java.util.Collections.list(
        load(directory.resolve("config/certificates/verifier-registration-certificate/verifier-registration-certificate.p12")).aliases()))
        .containsExactly("registration");
    var trust = load(directory.resolve("config/certificates/trust-list-signer/trust_source.p12"));
    assertThat(java.util.Collections.list(trust.aliases())).containsExactly("trust_source");
    var signerCertificate =
        (java.security.cert.X509Certificate) trust.getCertificate("trust_source");
    assertThat(signerCertificate.getBasicConstraints()).isEqualTo(-1);
    for (var file : List.of(directory.resolve("config/trust-source/signed/trusted-entities.json"),
        directory.resolve("config/trust-source/signed/status-list.jwt"))) {
      String token = Files.readString(file);
      assertThat(new TrustListSigner().verifyJws(token, signerCertificate.getPublicKey())).isTrue();
      assertThat(new TrustListSigner().verifyJws(token,
          authorities.loadPublic(AuthorityRole.TRUST_SOURCE).getPublicKey())).isFalse();
      assertThat(JWSObject.parse(token).getHeader().getX509CertChain().getFirst().decode())
          .isEqualTo(signerCertificate.getEncoded());
    }
    String pidToken =
        Files.readString(directory.resolve("config/pid-issuer/issuer_wrprc.jwt"));
    assertThat(
        new TrustListSigner().verifyJws(pidToken, pid.getCertificate("pid_issuer").getPublicKey()))
        .isTrue();
    assertThat(JWSObject.parse(pidToken).getHeader().getX509CertChain()).hasSize(1);
    assertThat(JWSObject.parse(pidToken).getPayload().toJSONObject()).containsEntry("iss",
        "did:web:localhost");
    assertThat(
        Files.isRegularFile(directory.resolve("config/pid-issuer/issuer_wrprc.json")))
        .isTrue();
    var registration = JWSObject.parse(Files.readString(
        directory.resolve("config/certificates/verifier-registration-certificate/registration_certificate.jwt")));
    assertThat(registration.getHeader().getType().toString()).isEqualTo("rc-wrp+jwt");
    assertThat(registration.getHeader().getX509CertChain()).hasSize(2);
    assertThat(new TrustListSigner().verifyJws(registration.serialize(),
        load(directory.resolve("config/certificates/verifier-registration-certificate/verifier-registration-certificate.p12"))
            .getCertificate("registration").getPublicKey()))
        .isTrue();
    var payload = JsonMapper.builder().build().readTree(registration.getPayload().toString());
    assertThat(payload.path("service_identifier").asString()).isEqualTo("wallet-ecosystem");
    assertThat(
        payload.path("credentials").get(0).path("claim").get(4).path("path").get(1).asString())
        .isEqualTo("street_address");
    assertThat(Files.readString(
        directory.resolve("config/certificates/verifier-registration-certificate/registration_certificate.env")))
        .isEqualTo(
            "VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE=" + registration.serialize() + "\n");
    for (var role : AuthorityRole.values()) {
      assertThat(new CertificateAuthorityManager()
          .readCertificatePem(directory.resolve("config/trust-source")
              .resolve(role.directory()).resolve("ca.pem")))
          .isEqualTo(authorities.loadPublic(role));
      assertThat(
          Files.isRegularFile(directory.resolve("config/trust-source")
              .resolve(role.directory()).resolve("revocation-list.pem")))
          .isTrue();
    }
    try (var files =
        Files.walk(directory.resolve("config/trust-source"))) {
      assertThat(
          files.filter(Files::isRegularFile).map(path -> path.getFileName().toString()).toList())
          .noneMatch(name -> name.contains("private") || name.endsWith(".p12"));
    }
  }

  @Test
  void pid_rotation_preserves_authorities_and_unrelated_outputs_without_other_passwords()
      throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var provisioner = EcosystemFixture.provisioner();
    provisioner.initializeAuthorities(config, EcosystemFixture.quiet());
    provisioner.generate(config, List.of(), EcosystemFixture.quiet());
    byte[] root = Files.readAllBytes(directory.resolve("state/authorities")
        .resolve(AuthorityRole.PID_ISSUER.directory()).resolve("ca.pem"));
    byte[] pidBefore =
        Files.readAllBytes(directory.resolve("config/certificates/issuer/pid_issuer.p12"));
    byte[] walletBefore =
        Files.readAllBytes(directory.resolve("config/certificates/wallet-provider/wallet_provider.p12"));
    byte[] loteBefore =
        Files.readAllBytes(directory.resolve("config/trust-source/signed/trusted-entities.json"));
    var selected = new EcosystemProvisioner(new SecretResolver(
        name -> name.equals("PID_ISSUER_KEYSTORE_PASSWORD") ? "test-password" : null));
    selected.generate(config, List.of("pid-issuer"), EcosystemFixture.quiet());
    assertThat(Files.readAllBytes(directory.resolve("config/certificates/issuer/pid_issuer.p12")))
        .isNotEqualTo(pidBefore);
    assertThat(Files.readAllBytes(directory.resolve("config/certificates/wallet-provider/wallet_provider.p12")))
        .isEqualTo(walletBefore);
    assertThat(
        Files.readAllBytes(directory.resolve("config/trust-source/signed/trusted-entities.json")))
        .isEqualTo(loteBefore);
    assertThat(Files.readAllBytes(directory.resolve("state/authorities")
        .resolve(AuthorityRole.PID_ISSUER.directory()).resolve("ca.pem")))
        .isEqualTo(root);
  }

  @Test
  void lote_only_needs_public_authorities_and_the_trust_signer_password() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var outputDirectory = Path.of(config.outputDirectory());
    var provisioner = EcosystemFixture.provisioner();
    provisioner.initializeAuthorities(config, EcosystemFixture.quiet());
    provisioner.generate(config, List.of(), EcosystemFixture.quiet());
    var before = snapshot(outputDirectory);
    for (var role : AuthorityRole.values())
      Files.delete(directory.resolve("state/authorities").resolve(role.directory())
          .resolve("ca_private_key.pem"));
    var selected = new EcosystemProvisioner(new SecretResolver(
        name -> name.equals("TRUST_SOURCE_KEYSTORE_PASSWORD") ? "test-password" : null));
    selected.generate(config, List.of("lote"), EcosystemFixture.quiet());
    var after = snapshot(outputDirectory);
    before.remove(directory.resolve("config/trust-source/signed/trusted-entities.json").toString());
    after.remove(directory.resolve("config/trust-source/signed/trusted-entities.json").toString());
    assertThat(after).isEqualTo(before);
  }

  @Test
  void trust_signer_rotation_also_refreshes_both_signed_documents() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var provisioner = EcosystemFixture.provisioner();
    provisioner.initializeAuthorities(config, EcosystemFixture.quiet());
    provisioner.generate(config, List.of(), EcosystemFixture.quiet());
    var previousKey =
        load(directory.resolve("config/certificates/trust-list-signer/trust_source.p12"))
            .getCertificate("trust_source").getPublicKey();
    var selected = new EcosystemProvisioner(new SecretResolver(
        name -> name.equals("TRUST_SOURCE_KEYSTORE_PASSWORD") ? "test-password" : null));
    selected.generate(config, List.of("trust-source"), EcosystemFixture.quiet());
    var currentKey =
        load(directory.resolve("config/certificates/trust-list-signer/trust_source.p12"))
            .getCertificate("trust_source").getPublicKey();
    assertThat(currentKey).isNotEqualTo(previousKey);
    for (var file : List.of(directory.resolve("config/trust-source/signed/trusted-entities.json"),
        directory.resolve("config/trust-source/signed/status-list.jwt"))) {
      assertThat(new TrustListSigner().verifyJws(Files.readString(file), currentKey)).isTrue();
      assertThat(new TrustListSigner().verifyJws(Files.readString(file), previousKey)).isFalse();
    }
  }

  @Test
  void missing_passwords_fail_before_any_output_is_changed() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var outputDirectory = Path.of(config.outputDirectory());
    EcosystemFixture.provisioner().initializeAuthorities(config, EcosystemFixture.quiet());
    var before = snapshot(outputDirectory);
    var provisioner = new EcosystemProvisioner(new SecretResolver(
        name -> name.equals("TRUST_SOURCE_KEYSTORE_PASSWORD") ? null : "test-password"));
    assertThatThrownBy(() -> provisioner.generate(config, List.of(), EcosystemFixture.quiet()))
        .hasMessageContaining("not set or empty");
    assertThat(snapshot(outputDirectory)).isEqualTo(before);
  }

  @Test
  void generation_never_creates_missing_authorities() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var outputDirectory = Path.of(config.outputDirectory());
    var stateDirectory = Path.of(config.stateDirectory());
    assertThatThrownBy(() -> EcosystemFixture.provisioner().generate(config, List.of("pid-issuer"),
        EcosystemFixture.quiet())).hasMessageContaining("init-authorities");
    assertThat(Files.exists(stateDirectory)).isFalse();
    assertThat(Files.exists(outputDirectory)).isFalse();
  }

  @Test
  void unknown_targets_fail_before_reading_secrets_or_writing_files() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var provisioner = new EcosystemProvisioner(new SecretResolver(name -> {
      throw new AssertionError("Secret lookup was not expected");
    }));
    assertThatThrownBy(
        () -> provisioner.generate(config, List.of("pid-issure"), EcosystemFixture.quiet()))
        .hasMessageContaining("Unknown generation target");
    assertThat(Files.exists(Path.of(config.outputDirectory()))).isFalse();
  }

  @Test
  void trust_documents_do_not_create_a_missing_signer_implicitly() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    EcosystemFixture.provisioner().initializeAuthorities(config, EcosystemFixture.quiet());
    assertThatThrownBy(() -> EcosystemFixture.provisioner().generate(config, List.of("lote"),
        EcosystemFixture.quiet())).hasMessageContaining("KeyStore file not found");
    assertThat(Files.exists(
        directory.resolve("config/certificates/trust-list-signer/trust_source.p12")))
        .isFalse();
  }

  @Test
  void artifact_paths_are_read_from_yaml_for_generation_and_signer_reuse() throws Exception {
    var artifacts = List.of(
        "certificates/issuer/pid_issuer.p12",
        "certificates/wallet-provider/wallet_provider.p12",
        "certificates/verifier-access-certificate/verifier-access-certificate.p12",
        "certificates/verifier-registration-certificate/verifier-registration-certificate.p12",
        "pid-issuer/issuer_wrprc.jwt",
        "pid-issuer/issuer_wrprc.json",
        "certificates/verifier-registration-certificate/registration_certificate.jwt",
        "certificates/verifier-registration-certificate/registration_certificate.env",
        "certificates/trust-list-signer/trust_source.p12",
        "certificates/trust-list-signer/trust_source_cert.pem",
        "trust-source/signed/trusted-entities.json",
        "trust-source/signed/status-list.jwt");
    String yaml = EcosystemFixture.yaml(directory);
    for (String artifact : artifacts) {
      yaml = yaml.replace(": " + artifact + "\n", ": relocated/" + artifact + "\n");
    }
    yaml = yaml.replace("publicationDirectory: trust-source", "publicationDirectory: relocated/trust-source")
        .replace("rootCrlFile: trust-source/revocation-list.pem", "rootCrlFile: relocated/trust-source/revocation-list.pem");
    Path file = directory.resolve("relocated.yaml");
    Files.writeString(file, yaml);
    var config = new ConfigurationLoader().load(file);
    var provisioner = EcosystemFixture.provisioner();
    provisioner.initializeAuthorities(config, EcosystemFixture.quiet());
    provisioner.generate(config, List.of(), EcosystemFixture.quiet());
    provisioner.generate(config, List.of("lote", "status-list"), EcosystemFixture.quiet());
    for (String artifact : artifacts) {
      assertThat(Files.isRegularFile(directory.resolve("config/relocated").resolve(artifact)))
          .as(artifact).isTrue();
      assertThat(Files.exists(directory.resolve("config").resolve(artifact))).isFalse();
    }
    assertThat(Files.isRegularFile(directory.resolve("config/relocated/trust-source/pid-issuer/ca.pem")))
        .isTrue();
    assertThat(Files.isRegularFile(directory.resolve("config/relocated/trust-source/revocation-list.pem")))
        .isTrue();
  }

  private KeyStore load(Path file) {
    return new KeystoreManager().loadKeyStore(file, "test-password".toCharArray());
  }

  private Map<String, String> snapshot(Path root) throws Exception {
    Map<String, String> result = new TreeMap<>();
    try (var paths = Files.walk(root)) {
      for (Path path : paths.filter(Files::isRegularFile).toList())
        result.put(path.toString(),
            java.util.Base64.getEncoder().encodeToString(Files.readAllBytes(path)));
    }
    return result;
  }
}
