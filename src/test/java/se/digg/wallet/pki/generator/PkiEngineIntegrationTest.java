// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.generator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import se.digg.wallet.pki.TestEnvironment;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.EnvironmentConfiguration;
import se.digg.wallet.pki.config.EnvironmentConfiguration.Authority;
import se.digg.wallet.pki.config.PkiConfigurationException;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.generator.GenerationPlan.Action;
import se.digg.wallet.pki.generator.GenerationPlan.Operation;
import se.digg.wallet.pki.storage.ArtifactStore;

class PkiEngineIntegrationTest {
  @TempDir
  Path directory;
  private final PkiEngine engine = new PkiEngine(new SecretResolver(), TestEnvironment.CLOCK);

  @Test
  void plans_become_stale_after_another_generation_is_committed() throws Exception {
    Path source = TestEnvironment.create(directory);
    var plan = engine.plan(source, Operation.ENSURE, List.of());
    var first = engine.apply(plan);

    assertThatThrownBy(() -> engine.apply(plan)).isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("generation changed");

    assertThat(engine.verify(source).generation()).isEqualTo(first.generation());
  }

  @Test
  void changing_configuration_invalidates_an_existing_plan() throws Exception {
    Path source = TestEnvironment.create(directory);
    var plan = engine.plan(source, Operation.ENSURE, List.of());
    Files.writeString(source, Files.readString(source).replace("country: SE", "country: NO"));

    assertThatThrownBy(() -> engine.apply(plan)).isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("Configuration changed since planning");

    assertThat(directory.resolve("state")).doesNotExist();
  }

  @Test
  void unknown_targets_never_create_authorities() throws Exception {
    Path source = TestEnvironment.create(directory);

    assertThatThrownBy(() -> engine.plan(source, Operation.ENSURE, List.of("identity:typo")))
        .isInstanceOf(PkiConfigurationException.class).hasMessageContaining("Unknown target");

    assertThat(directory.resolve("state")).doesNotExist();
  }

  @Test
  void trust_anchor_rotation_requires_coordinated_rollover() throws Exception {
    Path source = TestEnvironment.create(directory);

    assertThatThrownBy(() -> engine.plan(source, Operation.ROTATE, List.of("authority:pid-issuer")))
        .isInstanceOf(PkiConfigurationException.class).hasMessageContaining("separate rollover");

    assertThat(directory.resolve("state")).doesNotExist();
  }

  @Test
  void document_renewal_preserves_identity_keys() throws Exception {
    Path source = TestEnvironment.create(directory);
    var first = engine.apply(engine.plan(source, Operation.ENSURE, List.of()));
    Clock later =
        Clock.fixed(TestEnvironment.CLOCK.instant().plus(Duration.ofDays(340)), ZoneOffset.UTC);
    var laterEngine = new PkiEngine(new SecretResolver(), later);

    var plan = laterEngine.plan(source, Operation.ENSURE, List.of());
    var renewed = laterEngine.apply(plan);

    assertThat(plan.changes()).filteredOn(c -> c.reference().startsWith("identity:"))
        .allSatisfy(c -> assertThat(c.action()).isEqualTo(Action.REUSE));
    assertThat(plan.changes()).filteredOn(c -> c.reference().startsWith("document:"))
        .allSatisfy(c -> assertThat(c.action()).isEqualTo(Action.REBUILD));
    String identity = "private/certificates/issuer/pid_issuer.p12";
    assertThat(Files.readAllBytes(renewed.bundle().resolve(identity)))
        .isEqualTo(Files.readAllBytes(first.bundle().resolve(identity)));
    assertThat(laterEngine.verify(source).generation()).isEqualTo(renewed.generation());
  }

  @Test
  void document_renewal_requires_sufficient_signing_certificate_lifetime() throws Exception {
    Path source = TestEnvironment.create(directory);
    engine.apply(engine.plan(source, Operation.ENSURE, List.of()));
    Clock later =
        Clock.fixed(TestEnvironment.CLOCK.instant().plus(Duration.ofDays(800)), ZoneOffset.UTC);
    var laterEngine = new PkiEngine(new SecretResolver(), later);

    assertThatThrownBy(() -> laterEngine.plan(source, Operation.ENSURE, List.of("document:lote")))
        .isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("Signing identity cannot cover the renewal window");
  }

  @Test
  void verification_rejects_unmanifested_artifacts() throws Exception {
    Path source = TestEnvironment.create(directory);
    var generated = engine.apply(engine.plan(source, Operation.ENSURE, List.of()));
    Files.writeString(generated.bundle().resolve("public/unexpected.txt"), "unexpected");

    assertThatThrownBy(() -> engine.verify(source)).isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("Unmanifested artifacts");
  }

  @Test
  void temporarily_removing_authorities_preserves_their_pins() throws Exception {
    Path source = TestEnvironment.create(directory);
    String original = Files.readString(source);
    String extra = """
          - id: retained
            commonName: Retained CA
            create: true
        """;
    String extended = original.replace("authorities:\n", "authorities:\n" + extra);
    Files.writeString(source, extended);
    var first = engine.apply(engine.plan(source, Operation.ENSURE, List.of()));
    Path certificate = directory.resolve("state/generations/" + first.generation()
        + "/authority/retained/ca.pem");
    final byte[] pinned = Files.readAllBytes(certificate);
    Files.writeString(source, original);
    engine.apply(engine.plan(source, Operation.ENSURE, List.of()));
    Files.writeString(source, extended);

    var plan = engine.plan(source, Operation.ENSURE, List.of());
    var restored = engine.apply(plan);

    assertThat(plan.changes()).filteredOn(c -> c.reference().equals("authority:retained"))
        .singleElement().satisfies(c -> assertThat(c.action()).isEqualTo(Action.REUSE));
    assertThat(Files.readAllBytes(directory.resolve("state/generations/" + restored.generation()
        + "/authority/retained/ca.pem"))).isEqualTo(pinned);
  }

  @Test
  void imported_authorities_retain_their_original_certificates() throws Exception {
    Path source = TestEnvironment.create(directory);
    var local = engine.apply(engine.plan(source, Operation.ENSURE, List.of()));
    Path managed = managedConfiguration(source, local.generation());

    var stage = engine.apply(engine.plan(managed, Operation.ENSURE, List.of()));

    String certificate = "public/trust-source/pid-issuer/ca.pem";
    assertThat(Files.readAllBytes(stage.bundle().resolve(certificate)))
        .isEqualTo(Files.readAllBytes(local.bundle().resolve(certificate)));
    assertThat(engine.verify(managed).environment()).isEqualTo("stage");
  }

  @Test
  void imported_certificate_changes_invalidate_initial_plans() throws Exception {
    Path source = TestEnvironment.create(directory);
    var local = engine.apply(engine.plan(source, Operation.ENSURE, List.of()));
    Path managed = managedConfiguration(source, local.generation());
    var imported = new ConfigurationLoader().load(managed).authorities().getFirst();
    Path copy = directory.resolve("imported-ca.pem");
    Files.copy(Path.of(imported.certFile()), copy);
    Files.writeString(managed,
        Files.readString(managed).replace(imported.certFile(), copy.toString()));
    var plan = engine.plan(managed, Operation.ENSURE, List.of());
    Files.writeString(copy, Files.readString(copy) + "\n");

    assertThatThrownBy(() -> engine.apply(plan)).isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("Configuration changed since planning");

    assertThat(directory.resolve("managed-state")).doesNotExist();
  }

  @Test
  void mismatched_imported_private_keys_do_not_create_state() throws Exception {
    Path source = TestEnvironment.create(directory);
    var local = engine.apply(engine.plan(source, Operation.ENSURE, List.of()));
    Path managed = managedConfiguration(source, local.generation());
    Files.writeString(managed, Files.readString(managed)
        .replace("pid-issuer/ca_private_key.pem", "wallet-provider/ca_private_key.pem"));
    var plan = engine.plan(managed, Operation.ENSURE, List.of());

    assertThatThrownBy(() -> engine.apply(plan)).isInstanceOf(PkiConfigurationException.class)
        .hasMessageContaining("does not match");

    assertThat(directory.resolve("managed-state")).doesNotExist();
  }

  @Test
  void simultaneous_state_writers_are_rejected() throws Exception {
    Path source = TestEnvironment.create(directory);
    var plan = engine.plan(source, Operation.ENSURE, List.of());
    var store = new ArtifactStore(new ConfigurationLoader().load(source));

    try (var lock = store.lock()) {
      assertThat(lock.lock().isValid()).isTrue();
      assertThatThrownBy(() -> engine.apply(plan)).isInstanceOf(PkiConfigurationException.class);
    }

    assertThat(directory.resolve("bundles/current")).doesNotExist();
  }

  @Test
  void changed_static_inputs_are_exported_without_reissuing_certificates() throws Exception {
    Path source = TestEnvironment.create(directory);
    Path asset = directory.resolve("cps.md");
    Files.writeString(asset, "original");
    Files.writeString(source, Files.readString(source)
        .replace("file:" + Path.of("examples/assets/verifier-access-cps.md").toAbsolutePath(),
            "file:" + asset));
    engine.apply(engine.plan(source, Operation.ENSURE, List.of()));
    Files.writeString(asset, "updated");

    var plan = engine.plan(source, Operation.ENSURE, List.of());
    var updated = engine.apply(plan);

    assertThat(plan.changes()).allSatisfy(c -> assertThat(c.action()).isEqualTo(Action.REUSE));
    assertThat(Files.readString(
        updated.bundle().resolve("public/trust-source/verifier-access-certificate/cps.md")))
        .isEqualTo("updated");
  }

  private Path managedConfiguration(Path source, String generation) throws Exception {
    var config = new ConfigurationLoader().load(source);
    var imported = config.authorities().stream().map(a -> {
      Path location = directory.resolve("state/generations/" + generation + "/authority/" + a.id());
      return new Authority(a.id(), a.commonName(), false,
          location.resolve("ca_private_key.pem").toString(), location.resolve("ca.pem").toString(),
          a.certificateUrl(), a.crlUrl());
    }).toList();
    var managed =
        new EnvironmentConfiguration(1, "stage", directory.resolve("managed-state").toString(),
            directory.resolve("managed-bundles").toString(), imported, config.identities(),
            config.documents(),
            config.trustStores(), config.exports());
    Path destination = directory.resolve("managed.yaml");
    Files.writeString(destination, ArtifactStore.JSON.writeValueAsString(managed));
    return destination;
  }
}
