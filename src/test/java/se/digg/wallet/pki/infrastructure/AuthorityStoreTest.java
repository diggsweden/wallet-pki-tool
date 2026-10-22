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
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.support.EcosystemFixture;

class AuthorityStoreTest {
  @TempDir
  Path directory;

  @Test
  void repeated_initialization_preserves_all_authority_material() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var layout = new EcosystemLayout(config);
    var store = new AuthorityStore(config);
    var original = store.initialize(AuthorityRole.PID_ISSUER);
    var reloaded = store.initialize(AuthorityRole.PID_ISSUER);
    assertThat(reloaded.certificate()).isEqualTo(original.certificate());
    assertThat(reloaded.privateKey().getEncoded()).isEqualTo(original.privateKey().getEncoded());
    assertThat(reloaded.crl()).isEqualTo(original.crl());
    assertThat(Files.readAllBytes(layout.publication(AuthorityRole.PID_ISSUER).resolve("ca.pem")))
        .isEqualTo(
            Files.readAllBytes(layout.authority(AuthorityRole.PID_ISSUER).resolve("ca.pem")));
  }

  @Test
  void incomplete_authorities_are_never_replaced() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var layout = new EcosystemLayout(config);
    var store = new AuthorityStore(config);
    store.initialize(AuthorityRole.PID_ISSUER);
    Path key = layout.authority(AuthorityRole.PID_ISSUER).resolve("ca_private_key.pem");
    byte[] keyBefore = Files.readAllBytes(key);
    Files.delete(layout.authority(AuthorityRole.PID_ISSUER).resolve("ca.pem"));
    assertThatThrownBy(() -> store.initialize(AuthorityRole.PID_ISSUER))
        .hasMessageContaining("incomplete roots must be repaired");
    assertThat(Files.readAllBytes(key)).isEqualTo(keyBefore);
  }

  @Test
  void imported_authorities_preserve_the_supplied_crl_and_inputs() throws Exception {
    var manager = new CertificateAuthorityManager();
    var original = manager.createAuthority("external", "External CA");
    Path imported = directory.resolve("imported");
    manager.saveAuthority(original, imported);
    Path file = EcosystemFixture.configurationFile(directory);
    String yaml = Files.readString(file).replace(
        "    source: managed\n    commonName: DIGG Wallet PID Issuer CA",
        "    source: existing\n    certificateFile: " + imported.resolve("ca.pem")
            + "\n    privateKeyFile: " + imported.resolve("ca_private_key.pem")
            + "\n    crlFile: " + imported.resolve("revocation-list.pem"));
    Files.writeString(file, yaml);
    var config = new ConfigurationLoader().load(file);
    var store = new AuthorityStore(config);
    byte[] crlBefore = Files.readAllBytes(imported.resolve("revocation-list.pem"));
    assertThat(store.initialize(AuthorityRole.PID_ISSUER).certificate())
        .isEqualTo(original.certificate());
    assertThat(Files.readAllBytes(new EcosystemLayout(config).publication(AuthorityRole.PID_ISSUER)
        .resolve("revocation-list.pem"))).isEqualTo(crlBefore);
    assertThat(Files.readAllBytes(imported.resolve("revocation-list.pem"))).isEqualTo(crlBefore);
    assertThat(Files.exists(new EcosystemLayout(config).authority(AuthorityRole.PID_ISSUER)))
        .isFalse();
  }

  @Test
  void mismatched_ca_keys_are_rejected_without_replacing_them() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var layout = new EcosystemLayout(config);
    var store = new AuthorityStore(config);
    store.initialize(AuthorityRole.PID_ISSUER);
    Path key = layout.authority(AuthorityRole.PID_ISSUER).resolve("ca_private_key.pem");
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
    var layout = new EcosystemLayout(config);
    var store = new AuthorityStore(config);
    store.initialize(AuthorityRole.PID_ISSUER);
    Files.delete(layout.authority(AuthorityRole.PID_ISSUER).resolve("revocation-list.pem"));
    assertThatThrownBy(() -> store.initialize(AuthorityRole.PID_ISSUER))
        .hasMessageContaining("revocation-list.pem");
  }

  @Test
  void a_different_authoritys_crl_is_rejected() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    var layout = new EcosystemLayout(config);
    var store = new AuthorityStore(config);
    store.initialize(AuthorityRole.PID_ISSUER);
    store.initialize(AuthorityRole.WALLET_PROVIDER);
    Files.copy(layout.authority(AuthorityRole.WALLET_PROVIDER).resolve("revocation-list.pem"),
        layout.authority(AuthorityRole.PID_ISSUER).resolve("revocation-list.pem"),
        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    assertThatThrownBy(() -> store.load(AuthorityRole.PID_ISSUER))
        .hasMessageContaining("Invalid CRL");
  }

  @Test
  void changed_managed_authority_names_require_an_explicit_migration() throws Exception {
    var config = EcosystemFixture.configuration(directory);
    new AuthorityStore(config).initialize(AuthorityRole.PID_ISSUER);
    Path file = directory.resolve("ecosystem.yaml");
    Files.writeString(file,
        Files.readString(file).replace("DIGG Wallet PID Issuer CA", "Changed PID CA"));
    var changed = new ConfigurationLoader().load(file);
    assertThatThrownBy(() -> new AuthorityStore(changed).load(AuthorityRole.PID_ISSUER))
        .hasMessageContaining("subject differs");
  }
}
