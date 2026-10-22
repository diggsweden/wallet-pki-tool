// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.support.EcosystemFixture;

class AuthorityStoreTest {
  @TempDir
  Path directory;

  @ParameterizedTest
  @CsvSource({
      "PID_ISSUER, pid-issuer, DIGG Wallet PID Issuer CA",
      "WALLET_PROVIDER, wallet-provider, DIGG Wallet Provider CA",
      "VERIFIER_ACCESS, verifier-access-certificate, DIGG Wallet Verifier Access Certificate CA",
      "VERIFIER_REGISTRATION, verifier-registration-certificate, DIGG Wallet Verifier Registration Certificate CA",
      "TRUST_SOURCE, trust-source, DIGG Wallet Trust Source CA"
  })
  void fixed_authorities_preserve_existing_subjects_and_artifact_paths(
      AuthorityRole role, String roleDirectory, String commonName) throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var authority = new AuthorityStore(config).initialize(role);
    assertThat(authority.certificate().getSubjectX500Principal().getName())
        .contains("CN=" + commonName, "O=DIGG", "C=SE");
    Path state = directory.resolve("state/authorities").resolve(roleDirectory);
    Path publication = directory.resolve("config/trust-source").resolve(roleDirectory);
    assertThat(Files.isRegularFile(state.resolve("ca_private_key.pem"))).isTrue();
    for (String name : java.util.List.of("ca.pem", "revocation-list.pem")) {
      assertThat(Files.readAllBytes(publication.resolve(name)))
          .isEqualTo(Files.readAllBytes(state.resolve(name)));
    }
  }

  @Test
  void repeated_initialization_preserves_all_authority_material() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var store = new AuthorityStore(config);
    var original = store.initialize(AuthorityRole.PID_ISSUER);
    var reloaded = store.initialize(AuthorityRole.PID_ISSUER);
    assertThat(reloaded.certificate()).isEqualTo(original.certificate());
    assertThat(reloaded.privateKey().getEncoded()).isEqualTo(original.privateKey().getEncoded());
    assertThat(reloaded.crl()).isEqualTo(original.crl());
    assertThat(
        Files.readAllBytes(directory.resolve("config/trust-source")
            .resolve(AuthorityRole.PID_ISSUER.directory()).resolve("ca.pem")))
        .isEqualTo(
            Files.readAllBytes(directory.resolve("state/authorities")
                .resolve(AuthorityRole.PID_ISSUER.directory()).resolve("ca.pem")));
  }

  @Test
  void incomplete_authorities_are_never_replaced() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var store = new AuthorityStore(config);
    store.initialize(AuthorityRole.PID_ISSUER);
    Path key = directory.resolve("state/authorities").resolve(AuthorityRole.PID_ISSUER.directory())
        .resolve("ca_private_key.pem");
    byte[] keyBefore = Files.readAllBytes(key);
    Files
        .delete(directory.resolve("state/authorities").resolve(AuthorityRole.PID_ISSUER.directory())
            .resolve("ca.pem"));
    assertThatThrownBy(() -> store.initialize(AuthorityRole.PID_ISSUER))
        .hasMessageContaining("incomplete roots must be repaired");
    assertThat(Files.readAllBytes(key)).isEqualTo(keyBefore);
  }

  @Test
  void existing_authority_files_are_reused_without_replacing_keys_certificates_or_crls()
      throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var manager = new CertificateAuthorityManager();
    var original = manager.createAuthority("pid-issuer", "DIGG Wallet PID Issuer CA",
        config.organization());
    Path state =
        directory.resolve("state/authorities").resolve(AuthorityRole.PID_ISSUER.directory());
    manager.saveAuthority(original, state);
    var store = new AuthorityStore(config);
    byte[] crlBefore = Files.readAllBytes(state.resolve("revocation-list.pem"));
    var reloaded = store.initialize(AuthorityRole.PID_ISSUER);
    assertThat(reloaded.certificate()).isEqualTo(original.certificate());
    assertThat(reloaded.privateKey().getEncoded()).isEqualTo(original.privateKey().getEncoded());
    assertThat(reloaded.crl()).isEqualTo(original.crl());
    assertThat(
        Files.readAllBytes(directory.resolve("config/trust-source")
            .resolve(AuthorityRole.PID_ISSUER.directory())
            .resolve("revocation-list.pem")))
        .isEqualTo(crlBefore);
    assertThat(Files.readAllBytes(state.resolve("revocation-list.pem"))).isEqualTo(crlBefore);
  }

  @Test
  void mismatched_ca_keys_are_rejected_without_replacing_them() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var store = new AuthorityStore(config);
    store.initialize(AuthorityRole.PID_ISSUER);
    Path key = directory.resolve("state/authorities").resolve(AuthorityRole.PID_ISSUER.directory())
        .resolve("ca_private_key.pem");
    new EcKeyGenerator().writePrivateKeyPem(new EcKeyGenerator().generateKeyPair().getPrivate(),
        key);
    byte[] before = Files.readAllBytes(key);
    assertThatThrownBy(() -> store.load(AuthorityRole.PID_ISSUER))
        .hasMessageContaining("Private key does not match");
    assertThat(Files.readAllBytes(key)).isEqualTo(before);
  }

  @Test
  void missing_crls_are_rejected_instead_of_resetting_revocation_state() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var store = new AuthorityStore(config);
    store.initialize(AuthorityRole.PID_ISSUER);
    Files
        .delete(directory.resolve("state/authorities").resolve(AuthorityRole.PID_ISSUER.directory())
            .resolve("revocation-list.pem"));
    assertThatThrownBy(() -> store.initialize(AuthorityRole.PID_ISSUER))
        .hasMessageContaining("revocation-list.pem");
  }

  @Test
  void a_different_authoritys_crl_is_rejected() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var store = new AuthorityStore(config);
    store.initialize(AuthorityRole.PID_ISSUER);
    store.initialize(AuthorityRole.WALLET_PROVIDER);
    Files.copy(
        directory.resolve("state/authorities").resolve(AuthorityRole.WALLET_PROVIDER.directory())
            .resolve("revocation-list.pem"),
        directory.resolve("state/authorities").resolve(AuthorityRole.PID_ISSUER.directory())
            .resolve("revocation-list.pem"),
        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    assertThatThrownBy(() -> store.load(AuthorityRole.PID_ISSUER))
        .hasMessageContaining("Invalid CRL");
  }

  @Test
  void changed_organizations_require_an_explicit_authority_migration() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    new AuthorityStore(config).initialize(AuthorityRole.PID_ISSUER);
    Path file = directory.resolve("ecosystem.yaml");
    Files.writeString(file,
        Files.readString(file).replace("  name: DIGG\n", "  name: Changed Organization\n"));
    var changed = new ConfigurationLoader().load(file);
    assertThatThrownBy(() -> new AuthorityStore(changed).load(AuthorityRole.PID_ISSUER))
        .hasMessageContaining("subject differs");
  }
}
