// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.generator;

import com.nimbusds.jose.JWSObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.EnvironmentConfiguration;
import se.digg.wallet.pki.config.EnvironmentConfiguration.Identity;
import se.digg.wallet.pki.config.PkiConfigurationException;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.crypto.IdentityIssuer;
import se.digg.wallet.pki.generator.GenerationPlan.Operation;
import se.digg.wallet.pki.storage.ArtifactStore;
import se.digg.wallet.pki.storage.ArtifactStore.Manifest;
import se.digg.wallet.pki.storage.ArtifactStore.Resource;
import se.digg.wallet.pki.storage.ArtifactStore.Snapshot;
import se.digg.wallet.pki.trustlist.SignedDocumentGenerator;
import se.digg.wallet.pki.trustlist.TrustListSigner;

/** Plans, applies and verifies complete generations of an environment's trust artifacts. */
public final class PkiEngine {
  private final ConfigurationLoader configurations = new ConfigurationLoader();
  private final SecretResolver secrets;
  private final Clock clock;
  private final EcKeyGenerator keys = new EcKeyGenerator();
  private final CertificateAuthorityManager authorities;
  private final IdentityIssuer identities;
  private final SignedDocumentGenerator documents;
  private final GenerationPlanner planner;

  public PkiEngine() {
    this(new SecretResolver(), Clock.systemUTC());
  }

  public PkiEngine(SecretResolver secrets) {
    this(secrets, Clock.systemUTC());
  }

  public PkiEngine(SecretResolver secrets, Clock clock) {
    this.secrets = Objects.requireNonNull(secrets);
    this.clock = Objects.requireNonNull(clock);
    authorities = new CertificateAuthorityManager(keys, new SecureRandom(), clock);
    identities = new IdentityIssuer(clock, keys, authorities);
    documents = new SignedDocumentGenerator(clock, new TrustListSigner());
    planner = new GenerationPlanner(clock, authorities);
  }

  public GenerationPlan plan(Path configuration, Operation operation, List<String> targets) {
    EnvironmentConfiguration config = configurations.load(configuration);
    return planner.plan(configuration, config, new ArtifactStore(config).current(),
        Objects.requireNonNull(operation), targets == null ? List.of() : targets);
  }

  /** Applies exactly the inspected generation; stale plans are rejected before generating keys. */
  public GenerationReport apply(GenerationPlan plan) {
    EnvironmentConfiguration config = configurations.load(plan.configuration());
    require(GenerationPlanner.configurationDigest(config).equals(plan.configurationDigest()),
        "Configuration changed since planning; create a new plan");
    ArtifactStore store = new ArtifactStore(config);
    Map<String, char[]> passwords = new LinkedHashMap<>();
    try {
      resolveSecrets(config, plan.requiredSecrets(), passwords);
      Map<String, CertificateAuthority> material = preflightAuthorities(config, store.current());
      try (var lock = store.lock()) {
        require(lock.lock().isValid(), "Cannot acquire state lock");
        Snapshot current = store.current();
        require(
            Objects.equals(plan.baseGeneration(), current == null ? null : current.generation()),
            "Committed generation changed since planning; create a new plan");
        GenerationPlan fresh = planner.plan(plan.configuration(), config, current,
            plan.operation(), plan.targets());
        require(fresh.equals(plan), "Plan changed; create a new plan before applying");
        if (current != null) {
          verifyFiles(current.state(), current.manifest().stateFiles());
          verifyFiles(current.bundle(), current.manifest().files());
        }
        if (current != null
            && current.manifest().configurationDigest().equals(plan.configurationDigest())
            && plan.changes().stream().allMatch(c -> c.action() == GenerationPlan.Action.REUSE)) {
          verifyPublic(config, current.state(), current.manifest().resources(), material);
          return new GenerationReport(config.environment(), current.generation(), current.bundle(),
              plan.changes());
        }
        try (var staging = store.begin(current)) {
          Map<String, Resource> resources =
              build(config, plan, staging.state(), current, material, passwords);
          verifyPublic(config, staging.state(), resources, material);
          for (Identity identity : config.identities()) {
            char[] password = passwords.get("identity:" + identity.id());
            if (password != null) {
              identities.verifyIdentity(identity, material.get(identity.authority()).certificate(),
                  staging.state(), password);
            }
          }
          export(config, staging.state(), staging.bundle());
          require(
              GenerationPlanner.configurationDigest(configurations.load(plan.configuration()))
                  .equals(plan.configurationDigest()),
              "Configuration changed during generation");
          Manifest manifest = new Manifest(1, "0.1.0-SNAPSHOT", config.environment(),
              staging.generation(), plan.configurationDigest(), clock.instant().toString(),
              resources, hashes(staging.bundle()), hashes(staging.state()));
          Path published = staging.commit(manifest);
          return new GenerationReport(config.environment(), staging.generation(), published,
              plan.changes());
        }
      }
    } catch (Exception e) {
      if (e instanceof PkiConfigurationException configurationException) {
        throw configurationException;
      }
      throw new PkiConfigurationException("Generation failed; previous bundle remains current: "
          + e.getMessage(), e);
    } finally {
      passwords.values().forEach(p -> Arrays.fill(p, '\0'));
    }
  }

  /** Verifies published bytes and cryptographic consumer contracts without modifying files. */
  public GenerationReport verify(Path configuration) {
    EnvironmentConfiguration config = configurations.load(configuration);
    ArtifactStore store = new ArtifactStore(config);
    Snapshot current = store.current();
    require(current != null, "No committed generation exists");
    require(
        GenerationPlanner.configurationDigest(config)
            .equals(current.manifest().configurationDigest()),
        "Configuration differs from committed generation; plan and apply first");
    Map<String, char[]> passwords = new LinkedHashMap<>();
    try {
      List<String> required = new ArrayList<>();
      config.identities().forEach(i -> required.add("identity:" + i.id()));
      config.trustStores().forEach(t -> required.add("truststore:" + t.id()));
      resolveSecrets(config, required, passwords);
      verifyFiles(current.state(), current.manifest().stateFiles());
      verifyFiles(current.bundle(), current.manifest().files());
      var material = preflightAuthorities(config, current);
      verifyPublic(config, current.state(), current.manifest().resources(), material);
      var certificates = certificates(config, current.state(), material);
      for (Identity identity : config.identities()) {
        identities.verifyIdentity(identity, material.get(identity.authority()).certificate(),
            current.state(), passwords.get("identity:" + identity.id()));
      }
      for (var trustStore : config.trustStores()) {
        Map<String, X509Certificate> expected = new LinkedHashMap<>();
        trustStore.certificates()
            .forEach(c -> expected.put(c.alias(), certificates.get(c.reference())));
        identities.verifyTrustStore(current.state(), trustStore.id(), expected,
            passwords.get("truststore:" + trustStore.id()));
      }
      return new GenerationReport(config.environment(), current.generation(), current.bundle(),
          List.of());
    } catch (Exception e) {
      throw new PkiConfigurationException("Artifact verification failed: " + e.getMessage(), e);
    } finally {
      passwords.values().forEach(p -> Arrays.fill(p, '\0'));
    }
  }

  private Map<String, CertificateAuthority> preflightAuthorities(EnvironmentConfiguration config,
      Snapshot current) {
    Map<String, CertificateAuthority> material = new LinkedHashMap<>();
    for (var authority : config.authorities()) {
      if (authority.keyFile() != null) {
        material.put(authority.id(), identities.importAuthority(authority));
      } else if (current != null
          && current.manifest().resources().containsKey("authority:" + authority.id())) {
        material.put(authority.id(), identities.readAuthority(authority.id(),
            ArtifactStore.resource(current.state(), "authority:" + authority.id(), "")));
      }
    }
    return material;
  }

  private Map<String, Resource> build(EnvironmentConfiguration config, GenerationPlan plan,
      Path state, Snapshot previous, Map<String, CertificateAuthority> material,
      Map<String, char[]> passwords) throws Exception {
    Map<String, Resource> resources = new LinkedHashMap<>();
    if (previous != null) {
      previous.manifest().resources().forEach((reference, resource) -> {
        if (reference.startsWith("authority:")) {
          resources.put(reference, resource);
        }
      });
      plan.changes().forEach(change -> {
        Resource existing = previous.manifest().resources().get(change.reference());
        if (existing != null) {
          resources.put(change.reference(), existing);
        }
      });
    }
    for (var authority : config.authorities()) {
      String ref = "authority:" + authority.id();
      if (plan.changes(ref)) {
        CertificateAuthority ca = material.get(authority.id());
        if (ca == null) {
          ca = authorities.createAuthority(authority.id(), authority.commonName());
          material.put(authority.id(), ca);
        }
        identities.saveAuthority(ca, ArtifactStore.resource(state, ref, ""));
        resources.put(ref, new Resource(GenerationPlanner.authorityDigest(authority),
            ca.certificate().getNotAfter().toInstant().toString(),
            GenerationPlanner.certificateDigest(ca.certificate()), null));
      }
    }
    for (Identity identity : config.identities()) {
      String ref = "identity:" + identity.id();
      if (plan.changes(ref)) {
        Resource old = resources.get(ref);
        var authority = config.authorities().stream()
            .filter(a -> a.id().equals(identity.authority())).findFirst().orElseThrow();
        boolean rotate = plan.changes().stream().anyMatch(c -> c.reference().equals(ref)
            && c.action() == GenerationPlan.Action.ROTATE);
        var certificate = identities.issue(identity, authority, material.get(identity.authority()),
            state, passwords.get(ref), rotate, old == null ? null : old.primaryAlias());
        resources.put(ref, new Resource(GenerationPlanner.identityDigest(identity, config),
            certificate.getNotAfter().toInstant().toString(),
            GenerationPlanner.certificateDigest(certificate), identity.alias()));
      }
    }
    var certificates = certificates(config, state, material);
    for (var document : config.documents()) {
      String ref = "document:" + document.id();
      if (plan.changes(ref)) {
        Identity identity = config.identities().stream()
            .filter(i -> i.id().equals(document.signer())).findFirst().orElseThrow();
        var signing = identities.signingIdentity(state, identity.id(), identity.alias(),
            passwords.get("identity:" + identity.id()));
        Path path = ArtifactStore.resource(state, ref, ".jwt");
        int sequence = "lote".equals(document.type()) && Files.exists(path)
            ? SignedDocumentGenerator.nextSequence(Files.readString(path))
            : 1;
        var signed = documents.generate(document, signing, certificates, sequence);
        ArtifactStore.write(path, signed.token().getBytes(StandardCharsets.UTF_8), true);
        resources.put(ref, new Resource(ArtifactStore.digest(document),
            signed.expiresAt().toString(), null, null));
      }
    }
    for (var trustStore : config.trustStores()) {
      String ref = "truststore:" + trustStore.id();
      if (plan.changes(ref)) {
        Map<String, X509Certificate> entries = new LinkedHashMap<>();
        trustStore.certificates()
            .forEach(c -> entries.put(c.alias(), certificates.get(c.reference())));
        identities.writeTrustStore(state, trustStore.id(), entries, passwords.get(ref));
        Instant expiry = entries.values().stream().map(c -> c.getNotAfter().toInstant())
            .min(Instant::compareTo).orElseThrow();
        resources.put(ref,
            new Resource(ArtifactStore.digest(trustStore), expiry.toString(), null, null));
      }
    }
    return resources;
  }

  private Map<String, X509Certificate> certificates(EnvironmentConfiguration config, Path state,
      Map<String, CertificateAuthority> material) {
    Map<String, X509Certificate> result = new LinkedHashMap<>();
    config.authorities()
        .forEach(a -> result.put("authority:" + a.id(), material.get(a.id()).certificate()));
    config.identities()
        .forEach(i -> result.put("identity:" + i.id(), authorities.readCertificatePem(
            ArtifactStore.resource(state, "identity:" + i.id(), ".crt"))));
    return result;
  }

  private void verifyPublic(EnvironmentConfiguration config, Path state,
      Map<String, Resource> resources, Map<String, CertificateAuthority> material)
      throws Exception {
    var certificates = certificates(config, state, material);
    for (var entry : certificates.entrySet()) {
      X509Certificate certificate = entry.getValue();
      certificate.checkValidity(java.util.Date.from(clock.instant()));
      require(
          GenerationPlanner.certificateDigest(certificate)
              .equals(resources.get(entry.getKey()).certificateDigest()),
          "Certificate fingerprint differs from state: " + entry.getKey());
    }
    for (Identity identity : config.identities()) {
      X509Certificate leaf = certificates.get("identity:" + identity.id());
      leaf.verify(material.get(identity.authority()).publicKey());
    }
    for (var document : config.documents()) {
      Identity identity = config.identities().stream()
          .filter(i -> i.id().equals(document.signer())).findFirst().orElseThrow();
      documents.verify(document, Files.readString(ArtifactStore.resource(state,
          "document:" + document.id(), ".jwt")),
          List.of(certificates.get("identity:" + identity.id()),
              material.get(identity.authority()).certificate()),
          certificates);
    }
  }

  private void export(EnvironmentConfiguration config, Path state, Path bundle) throws Exception {
    ArtifactStore.directory(bundle.resolve("private"), true);
    ArtifactStore.directory(bundle.resolve("public"), false);
    for (var output : config.exports()) {
      byte[] contents;
      String source = output.source();
      switch (output.format()) {
        case "file" -> contents = Files.readAllBytes(Path.of(source.substring(5)));
        case "pkcs12" -> {
          contents = Files.readAllBytes(ArtifactStore.resource(state, source, ".p12"));
        }
        case "certificate" -> {
          Path path = source.startsWith("authority:")
              ? ArtifactStore.resource(state, source, "").resolve("ca.pem")
              : ArtifactStore.resource(state, source, ".crt");
          contents = Files.readAllBytes(path);
        }
        case "crl" -> contents = Files.readAllBytes(ArtifactStore.resource(state, source, "")
            .resolve("revocation-list.pem"));
        default -> {
          String token = Files.readString(ArtifactStore.resource(state, source, ".jwt"));
          if ("env".equals(output.format())) {
            contents = (output.variable() + "=" + token + "\n").getBytes(StandardCharsets.UTF_8);
          } else if ("json".equals(output.format())) {
            var jws = JWSObject.parse(token);
            contents = ArtifactStore.JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(
                Map.of("headers", jws.getHeader().toJSONObject(),
                    "payload", ArtifactStore.JSON.readTree(jws.getPayload().toString())));
          } else {
            contents = token.getBytes(StandardCharsets.UTF_8);
          }
        }
      }
      Path destination = bundle.resolve(output.path());
      ArtifactStore.write(destination, contents, "pkcs12".equals(output.format()));
      ArtifactStore.write(bundle.resolve(output.path() + ".license"),
          license(), "pkcs12".equals(output.format()));
    }
    ArtifactStore.write(bundle.resolve("manifest.json.license"), license(), false);
  }

  private byte[] license() {
    int year = clock.instant().atZone(ZoneOffset.UTC).getYear();
    return """
        SPDX-FileCopyrightText: %d Digg - Agency for Digital Government

        SPDX-License-Identifier: CC0-1.0
        """.formatted(year).getBytes(StandardCharsets.UTF_8);
  }

  private void resolveSecrets(EnvironmentConfiguration config, List<String> required,
      Map<String, char[]> resolved) {
    for (String reference : required) {
      if (reference.startsWith("identity:")) {
        var identity = config.identities().stream()
            .filter(i -> reference.equals("identity:" + i.id())).findFirst().orElseThrow();
        resolved.put(reference, secrets.resolve(identity.passwordEnv(), identity.passwordFile()));
      } else {
        var trustStore = config.trustStores().stream()
            .filter(t -> reference.equals("truststore:" + t.id())).findFirst().orElseThrow();
        resolved.put(reference,
            secrets.resolve(trustStore.passwordEnv(), trustStore.passwordFile()));
      }
    }
  }

  private static Map<String, String> hashes(Path root) throws Exception {
    Map<String, String> hashes = new LinkedHashMap<>();
    try (var paths = Files.walk(root)) {
      for (Path path : paths.sorted().toList()) {
        ArtifactStore.rejectSymlinks(path);
        if (Files.isRegularFile(path) && !path.equals(root.resolve("manifest.json"))) {
          hashes.put(root.relativize(path).toString(),
              ArtifactStore.digest(Files.readAllBytes(path)));
        }
      }
    }
    return hashes;
  }

  private static void verifyFiles(Path root, Map<String, String> hashes) throws Exception {
    Map<String, String> actual = hashes(root);
    for (var entry : hashes.entrySet()) {
      Path path = root.resolve(entry.getKey()).normalize();
      require(path.startsWith(root), "Manifest path escapes generation");
      ArtifactStore.rejectSymlinks(path);
      require(entry.getValue().equals(actual.get(entry.getKey())),
          "Artifact digest mismatch: " + entry.getKey());
    }
    require(actual.keySet().equals(hashes.keySet()), "Unmanifested artifacts found in generation");
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new PkiConfigurationException(message);
    }
  }
}
