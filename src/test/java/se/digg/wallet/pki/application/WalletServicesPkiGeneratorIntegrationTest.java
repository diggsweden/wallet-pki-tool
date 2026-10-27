// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSObject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
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

class WalletServicesPkiGeneratorIntegrationTest {
  @TempDir
  Path directory;

  @Nested
  class GeneratedEcosystem {
    private AuthorityStore authorities;

    @BeforeEach
    void generate() throws Exception {
      var config = EcosystemFixture.configuration(directory);
      EcosystemFixture.initializeAuthorities(config);
      EcosystemFixture.provisioner().generate(config, EcosystemFixture.quiet());
      authorities = new AuthorityStore(config);
    }

    @Test
    void all_consumer_artifacts_are_written() throws Exception {
      for (String relative : List.of("certificates/issuer/pid_issuer.p12",
          "certificates/wallet-attestation-issuer/wallet_attestation_issuer.p12",
          "certificates/verifier-access-certificate/verifier-access-certificate.p12",
          "certificates/verifier-registration-certificate/verifier-registration-certificate.p12",
          "certificates/trust-list-signer/trust_source.p12", "pid-issuer/issuer_wrprc.jwt",
          "certificates/verifier-registration-certificate/registration_certificate.env",
          "trust-source/signed/trusted-entities.json", "trust-source/signed/status-list.jwt")) {
        assertThat(Files.isRegularFile(directory.resolve("config").resolve(relative)))
            .as(relative).isTrue();
      }
    }

    @Test
    void participant_keystores_use_their_own_keys_and_authority_chains() throws Exception {
      assertKeystore("issuer/pid_issuer.p12", AuthorityRole.PID_ISSUER,
          "pid_issuer", "nonce-encryption", "request-encryption");
      assertKeystore("wallet-attestation-issuer/wallet_attestation_issuer.p12",
          AuthorityRole.WALLET_ATTESTATION_ISSUER, "wallet_attestation_issuer");
      assertKeystore("verifier-access-certificate/verifier-access-certificate.p12",
          AuthorityRole.VERIFIER_ACCESS, "verifier_access_certificate");
      assertKeystore("verifier-registration-certificate/verifier-registration-certificate.p12",
          AuthorityRole.VERIFIER_REGISTRATION, "registration");
      assertKeystore("trust-list-signer/trust_source.p12", AuthorityRole.TRUST_SOURCE,
          "trust_source");
    }

    @Test
    void trust_documents_are_signed_by_the_leaf_key_instead_of_the_authority() throws Exception {
      var trust = load(directory.resolve("config/certificates/trust-list-signer/trust_source.p12"));
      assertThat(Collections.list(trust.aliases())).containsExactly("trust_source");
      var signerCertificate =
          (X509Certificate) trust.getCertificate("trust_source");
      assertThat(signerCertificate.getBasicConstraints()).isEqualTo(-1);
      for (var file : List.of(directory.resolve("config/trust-source/signed/trusted-entities.json"),
          directory.resolve("config/trust-source/signed/status-list.jwt"))) {
        String token = Files.readString(file);
        assertThat(new TrustListSigner().verifyJws(token, signerCertificate.getPublicKey()))
            .isTrue();
        assertThat(new TrustListSigner().verifyJws(token,
            authorities.loadPublic(AuthorityRole.TRUST_SOURCE).getPublicKey())).isFalse();
        assertThat(JWSObject.parse(token).getHeader().getX509CertChain().getFirst().decode())
            .isEqualTo(signerCertificate.getEncoded());
      }
    }

    @Test
    void registration_documents_match_their_signing_keystores() throws Exception {
      var pid = load(directory.resolve("config/certificates/issuer/pid_issuer.p12"));
      String pidToken = Files.readString(directory.resolve("config/pid-issuer/issuer_wrprc.jwt"));
      assertThat(new TrustListSigner().verifyJws(pidToken,
          pid.getCertificate("pid_issuer").getPublicKey())).isTrue();
      assertThat(JWSObject.parse(pidToken).getHeader().getX509CertChain()).hasSize(1);
      assertThat(JWSObject.parse(pidToken).getPayload().toJSONObject())
          .containsEntry("iss", "did:web:localhost");
      assertThat(directory.resolve("config/pid-issuer/issuer_wrprc.json")).isRegularFile();

      Path registrationDirectory = directory.resolve(
          "config/certificates/verifier-registration-certificate");
      String token =
          Files.readString(registrationDirectory.resolve("registration_certificate.jwt"));
      var store = load(registrationDirectory.resolve("verifier-registration-certificate.p12"));
      assertThat(new TrustListSigner().verifyJws(token,
          store.getCertificate("registration").getPublicKey())).isTrue();
      var registration = JWSObject.parse(token);
      assertThat(registration.getHeader().getType().toString()).isEqualTo("rc-wrp+jwt");
      assertThat(registration.getHeader().getX509CertChain()).hasSize(2);
      var payload = JsonMapper.builder().build().readTree(registration.getPayload().toString());
      assertThat(payload.path("service_identifier").asString()).isEqualTo("wallet-ecosystem");
      assertThat(Files.readString(registrationDirectory.resolve("registration_certificate.env")))
          .isEqualTo("VERIFIER_INTENDEDUSES_0_REGISTRATIONCERTIFICATE=" + token + "\n");
    }

    @Test
    void public_authority_outputs_contain_no_private_keys_or_keystores() throws Exception {
      Path published = directory.resolve("config/trust-source");
      var certificates = new CertificateAuthorityManager();
      for (var role : AuthorityRole.values()) {
        Path roleDirectory = published.resolve(role.directory());
        assertThat(certificates.readCertificatePem(roleDirectory.resolve("ca.pem")))
            .isEqualTo(authorities.loadPublic(role));
        assertThat(roleDirectory.resolve("revocation-list.pem")).isRegularFile();
      }
      try (var files = Files.walk(published)) {
        assertThat(files.filter(Files::isRegularFile).map(published::relativize)
            .map(Path::toString).toList())
            .noneMatch(name -> name.contains("private") || name.endsWith(".p12"));
      }
    }

    private void assertKeystore(String file, AuthorityRole role, String... aliases)
        throws Exception {
      var store = load(directory.resolve("config/certificates").resolve(file));
      assertThat(Collections.list(store.aliases())).containsExactlyInAnyOrder(aliases);
      var authority = authorities.loadPublic(role);
      for (String alias : aliases) {
        assertThat(store.getKey(alias, "test-password".toCharArray())).as(alias).isNotNull();
        var chain = store.getCertificateChain(alias);
        assertThat(chain).as(alias).hasSize(2);
        assertThat(chain[1]).as(alias).isEqualTo(authority);
        chain[0].verify(authority.getPublicKey());
      }
    }
  }

  @Test
  void artifact_paths_are_read_from_yaml_for_generation_and_signer_reuse() throws Exception {
    var artifacts = List.of(
        "certificates/issuer/pid_issuer.p12",
        "certificates/wallet-attestation-issuer/wallet_attestation_issuer.p12",
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
    yaml = yaml
        .replace("directory: trust-source",
            "directory: relocated/trust-source")
        .replace("rootCrlFile: trust-source/revocation-list.pem",
            "rootCrlFile: relocated/trust-source/revocation-list.pem");
    Path file = directory.resolve("relocated.yaml");
    Files.writeString(file, yaml);
    var config = new ConfigurationLoader().load(file);
    var provisioner = EcosystemFixture.provisioner();
    EcosystemFixture.initializeAuthorities(config);
    provisioner.generate(config, EcosystemFixture.quiet());
    var documents = new TrustSourceFlow(new SecretResolver(name -> "test-password"));
    documents.generateLote(config, EcosystemFixture.quiet());
    for (String artifact : artifacts) {
      assertThat(Files.isRegularFile(directory.resolve("config/relocated").resolve(artifact)))
          .as(artifact).isTrue();
      assertThat(Files.exists(directory.resolve("config").resolve(artifact))).isFalse();
    }
    assertThat(
        Files.isRegularFile(directory.resolve("config/relocated/trust-source/pid-issuer/ca.pem")))
        .isTrue();
    assertThat(
        Files.isRegularFile(directory.resolve("config/relocated/trust-source/revocation-list.pem")))
        .isTrue();
  }

  private KeyStore load(Path file) {
    return new KeystoreManager().loadKeyStore(file, "test-password".toCharArray());
  }
}
