// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.generator;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import se.digg.wallet.pki.config.EnvironmentConfiguration;
import se.digg.wallet.pki.config.EnvironmentConfiguration.Authority;
import se.digg.wallet.pki.config.EnvironmentConfiguration.Identity;
import se.digg.wallet.pki.config.PkiConfigurationException;
import se.digg.wallet.pki.crypto.CertificateAuthorityManager;
import se.digg.wallet.pki.generator.GenerationPlan.Action;
import se.digg.wallet.pki.generator.GenerationPlan.Change;
import se.digg.wallet.pki.generator.GenerationPlan.Operation;
import se.digg.wallet.pki.storage.ArtifactStore;
import se.digg.wallet.pki.storage.ArtifactStore.Resource;
import se.digg.wallet.pki.storage.ArtifactStore.Snapshot;

/** Computes resource changes from explicit references without mutating state. */
final class GenerationPlanner {
  private final Clock clock;
  private final CertificateAuthorityManager authorities;

  GenerationPlanner(Clock clock, CertificateAuthorityManager authorities) {
    this.clock = clock;
    this.authorities = authorities;
  }

  GenerationPlan plan(Path source, EnvironmentConfiguration config, Snapshot current,
      Operation operation, List<String> requested) {
    final Set<String> targets = new LinkedHashSet<>(requested);
    Set<String> known = new LinkedHashSet<>();
    config.authorities().forEach(a -> known.add("authority:" + a.id()));
    config.identities().forEach(i -> known.add("identity:" + i.id()));
    config.documents().forEach(d -> known.add("document:" + d.id()));
    config.trustStores().forEach(t -> known.add("truststore:" + t.id()));
    for (String target : targets) {
      require(known.contains(target), "Unknown target: " + target);
      require(operation == Operation.ENSURE || target.startsWith("identity:"),
          "Renewal and rotation target identities; trust anchors require a separate rollover");
    }
    require(operation == Operation.ENSURE || !targets.isEmpty(),
        "Renewal and rotation require explicit identity targets");
    Map<String, Resource> previous = current == null ? Map.of() : current.manifest().resources();
    List<Change> changes = new ArrayList<>();
    Set<String> changed = new LinkedHashSet<>();
    Set<String> secrets = new LinkedHashSet<>();
    Map<String, Instant> authorityExpiries = new LinkedHashMap<>();
    Map<String, Instant> identityExpiries = new LinkedHashMap<>();

    for (Authority authority : config.authorities()) {
      String ref = "authority:" + authority.id();
      Resource existing = previous.get(ref);
      Instant authorityExpiry =
          clock.instant().plus(CertificateAuthorityManager.DEFAULT_CA_VALIDITY);
      if (authority.certFile() != null) {
        var certificate = authorities.readCertificatePem(Path.of(authority.certFile()));
        authorityExpiry = certificate.getNotAfter().toInstant();
        checkValidity(certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant(),
            ref);
        if (existing != null) {
          require(certificateDigest(certificate).equals(existing.certificateDigest()),
              "Imported trust anchor changed: " + ref
                  + "; perform a separate trust-anchor rollover");
        }
      } else if (existing == null) {
        require(authority.create(), "Missing persistent authority: " + ref
            + "; import its key/certificate or explicitly enable create for development");
      }
      if (existing != null) {
        authorityExpiry = Instant.parse(existing.expiresAt());
        require(existing.specificationDigest().equals(authorityDigest(authority)),
            "Authority subject changed: " + ref + "; perform a separate trust-anchor rollover");
        checkValidity(Instant.MIN, Instant.parse(existing.expiresAt()), ref);
      }
      add(changes, changed, ref, existing == null ? Action.CREATE : Action.REUSE,
          existing == null ? "initialize authority" : "preserve trust anchor");
      authorityExpiries.put(authority.id(), authorityExpiry);
    }

    for (Identity identity : config.identities()) {
      String ref = "identity:" + identity.id();
      Resource existing = previous.get(ref);
      boolean selected = targets.isEmpty() || targets.contains(ref);
      Action action = Action.REUSE;
      String reason = "existing material is valid";
      if (existing == null) {
        require(selected,
            "Initialize the complete environment before selecting targets; missing " + ref);
        action = Action.CREATE;
        reason = "identity is missing";
      } else if (selected && operation == Operation.ROTATE) {
        action = Action.ROTATE;
        reason = "explicit key rotation";
      } else if (selected && (operation == Operation.RENEW
          || due(existing, identity.renewBeforeDays())
          || !existing.specificationDigest().equals(identityDigest(identity, config)))) {
        action = Action.RENEW;
        reason = "renew certificate and preserve existing keys";
      } else {
        require(selected || existing.specificationDigest().equals(identityDigest(identity, config)),
            "Configuration changed for unselected identity: " + ref + "; ensure all targets first");
        checkValidity(Instant.MIN, Instant.parse(existing.expiresAt()), ref);
      }
      add(changes, changed, ref, action, reason);
      if (action != Action.REUSE) {
        require(authorityExpiries.get(identity.authority())
            .isAfter(clock.instant().plus(Duration.ofDays(identity.renewBeforeDays()))),
            "Issuing authority cannot cover the renewal window for " + ref
                + "; coordinate trust-anchor rollover first");
        secrets.add(ref);
      }
      Instant expiry = action == Action.REUSE ? Instant.parse(existing.expiresAt())
          : clock.instant().plus(Duration.ofDays(identity.validityDays()));
      if (expiry.isAfter(authorityExpiries.get(identity.authority()))) {
        expiry = authorityExpiries.get(identity.authority());
      }
      identityExpiries.put(identity.id(), expiry);
    }

    for (var document : config.documents()) {
      String ref = "document:" + document.id();
      Resource existing = previous.get(ref);
      boolean selected = targets.isEmpty() || targets.contains(ref);
      boolean dependencyChanged = changed.contains("identity:" + document.signer())
          || document.entities().stream().anyMatch(e -> changed.contains(e.reference()));
      boolean rebuild = dependencyChanged || selected && (existing == null
          || due(existing, document.renewBeforeDays())
          || !existing.specificationDigest().equals(ArtifactStore.digest(document)));
      require(existing != null || rebuild,
          "Missing document: " + ref + "; initialize all targets first");
      if (!rebuild) {
        require(existing.specificationDigest().equals(ArtifactStore.digest(document)),
            "Configuration changed for unselected document: " + ref + "; ensure all targets first");
        checkValidity(Instant.MIN, Instant.parse(existing.expiresAt()), ref);
      }
      add(changes, changed, ref, rebuild ? Action.REBUILD : Action.REUSE,
          dependencyChanged ? "a referenced identity or certificate changed"
              : rebuild ? "document is missing, changed or due for renewal"
                  : "document is current");
      if (rebuild) {
        require(identityExpiries.get(document.signer())
            .isAfter(clock.instant().plus(Duration.ofDays(document.renewBeforeDays()))),
            "Signing identity cannot cover the renewal window for " + ref
                + "; renew its certificate first");
        secrets.add("identity:" + document.signer());
      }
    }

    for (var trustStore : config.trustStores()) {
      String ref = "truststore:" + trustStore.id();
      Resource existing = previous.get(ref);
      boolean rebuild =
          trustStore.certificates().stream().anyMatch(c -> changed.contains(c.reference()))
              || (targets.isEmpty() || targets.contains(ref)) && (existing == null
                  || !existing.specificationDigest().equals(ArtifactStore.digest(trustStore)));
      require(existing != null || rebuild,
          "Missing truststore: " + ref + "; initialize all targets first");
      require(rebuild || existing.specificationDigest().equals(ArtifactStore.digest(trustStore)),
          "Configuration changed for unselected truststore: " + ref + "; ensure all targets first");
      add(changes, changed, ref, rebuild ? Action.REBUILD : Action.REUSE,
          rebuild ? "certificate set changed or truststore is missing" : "truststore is current");
      if (rebuild) {
        secrets.add(ref);
      }
    }
    return new GenerationPlan(source.toAbsolutePath().normalize(), config.environment(),
        configurationDigest(config), current == null ? null : current.generation(), operation,
        List.copyOf(targets), changes, List.copyOf(secrets));
  }

  static String authorityDigest(Authority authority) {
    return ArtifactStore.digest(List.of(authority.id(), authority.commonName()));
  }

  static String configurationDigest(EnvironmentConfiguration config) {
    Map<String, String> inputs = new java.util.TreeMap<>();
    for (Authority authority : config.authorities()) {
      if (authority.certFile() != null) {
        inputs.put("authority:" + authority.id(), inputDigest(Path.of(authority.certFile())));
      }
    }
    for (var export : config.exports()) {
      if ("file".equals(export.format())) {
        inputs.put(export.source(), inputDigest(Path.of(export.source().substring(5))));
      }
    }
    return ArtifactStore.digest(List.of(config, inputs));
  }

  private static String inputDigest(Path input) {
    try {
      return ArtifactStore.digest(java.nio.file.Files.readAllBytes(input));
    } catch (java.io.IOException e) {
      throw new PkiConfigurationException("Cannot read planning input " + input, e);
    }
  }

  static String identityDigest(Identity identity, EnvironmentConfiguration config) {
    Authority authority = config.authorities().stream()
        .filter(a -> a.id().equals(identity.authority())).findFirst().orElseThrow();
    return ArtifactStore.digest(List.of(identity,
        authority.certificateUrl() == null ? "" : authority.certificateUrl(),
        authority.crlUrl() == null ? "" : authority.crlUrl()));
  }

  static String certificateDigest(java.security.cert.X509Certificate certificate) {
    try {
      return ArtifactStore.digest(certificate.getEncoded());
    } catch (java.security.cert.CertificateEncodingException e) {
      throw new PkiConfigurationException("Cannot encode certificate", e);
    }
  }

  private boolean due(Resource resource, int renewBeforeDays) {
    return !Instant.parse(resource.expiresAt())
        .isAfter(clock.instant().plus(Duration.ofDays(renewBeforeDays)));
  }

  private void checkValidity(Instant start, Instant end, String reference) {
    require(!start.isAfter(clock.instant()) && end.isAfter(clock.instant()),
        "Certificate or document is outside its validity period: " + reference);
  }

  private static void add(List<Change> changes, Set<String> changed, String ref, Action action,
      String reason) {
    changes.add(new Change(ref, action, reason));
    if (action != Action.REUSE) {
      changed.add(ref);
    }
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new PkiConfigurationException(message);
    }
  }
}
