// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import se.digg.wallet.pki.config.AuthorityConfig;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.PkiConfigurationException;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.domain.WalletRole;
import se.digg.wallet.pki.domain.WalletTrustAnchors;
import se.digg.wallet.pki.infrastructure.AuthorityStore;
import se.digg.wallet.pki.infrastructure.EcosystemLayout;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.storage.ArtifactStore;
import se.digg.wallet.pki.storage.ArtifactStore.Manifest;
import se.digg.wallet.pki.storage.ArtifactStore.RoleState;
import se.digg.wallet.pki.storage.ArtifactStore.Snapshot;
import se.digg.wallet.pki.trustlist.RegistrationDocuments;

/** Executes the five named flows in an isolated generation under one writer lock. */
final class WalletProvisioner {
  private static final Duration RENEW_BEFORE = Duration.ofDays(30);
  private final SecretResolver secrets;
  private final Clock clock;

  WalletProvisioner(SecretResolver secrets, Clock clock) {
    this.secrets = secrets;
    this.clock = clock;
  }

  ProvisioningReport run(PkiConfiguration config, String workflow, Operation operation,
      List<String> arguments) {
    var selected = WalletRole.select(arguments, config.configuredRoles());
    require(operation != Operation.ROTATE && operation != Operation.RENEW || !arguments.isEmpty(),
        "Renewal and rotation require explicit wallet roles");
    var passwords = new EnumMap<WalletRole, char[]>(WalletRole.class);
    try {
      var store = new ArtifactStore(config, workflow);
      Snapshot current = store.current();
      if (current != null) {
        ArtifactStore.verify(current);
      }
      var previous = current == null ? Map.<WalletRole, RoleState>of() : current.manifest().roles();
      var pins = new EnumMap<WalletRole, String>(WalletRole.class);
      if (current != null) {
        pins.putAll(current.manifest().authorityPins());
      }
      var actions = new EnumMap<WalletRole, String>(WalletRole.class);
      var loaded = new EnumMap<WalletRole, CertificateAuthority>(WalletRole.class);
      var authorities = new AuthorityStore(config, clock);
      var before = current == null
          ? new EcosystemLayout(Path.of(config.stateDirectory()), Path.of(config.outputDirectory()))
          : new EcosystemLayout(current.state(), current.bundle());
      boolean publicationChanged = false;
      for (WalletRole role : selected) {
        AuthorityConfig authority = config.authority(role);
        if (authority.source() == AuthorityConfig.Source.EXISTING || pins.containsKey(role)) {
          var ca = authorities.load(role, before);
          String fingerprint = ArtifactStore.digest(ca.certificate().getEncoded());
          require(!pins.containsKey(role) || pins.get(role).equals(fingerprint),
              "Trust anchor changed for " + role.argument()
                  + "; coordinate authority rollover separately");
          loaded.put(role, ca);
          if (current != null
              && Files.exists(before.authority(role).resolve("revocation-list.pem"))) {
            var saved = new se.digg.wallet.pki.crypto.CertificateAuthorityManager()
                .readCrlPem(before.authority(role).resolve("revocation-list.pem"));
            publicationChanged |= !Arrays.equals(saved.getEncoded(), ca.crl().getEncoded());
          }
        } else {
          require(workflow.equals("ecosystem") && operation == Operation.ENSURE,
              "Missing authority for " + role.argument() + "; initialize through ecosystem ensure");
          require(!Files.exists(before.authority(role)),
              "Untracked authority material exists; restore its state instead of replacing it");
        }
        RoleState state = previous.get(role);
        String action;
        if (operation == Operation.VERIFY) {
          require(state != null, "No committed material for " + role.argument());
          require(state.configurationDigest().equals(digest(config, role)),
              "Configuration changed for " + role.argument() + "; ensure this role first");
          action = "VERIFY";
        } else if (state == null) {
          require(operation == Operation.ENSURE,
              "Ensure the role before renewal or rotation: " + role.argument());
          action = "CREATE";
        } else if (operation == Operation.ROTATE) {
          action = "ROTATE";
        } else if (operation == Operation.RENEW || due(state.certificateExpiresAt())
            || !state.configurationDigest().equals(digest(config, role))) {
          action = "RENEW";
        } else if (state.documentsExpireAt() != null && due(state.documentsExpireAt())) {
          action = "REFRESH_DOCUMENTS";
        } else {
          action = "REUSE";
        }
        actions.put(role, action);
        if (!action.equals("REUSE")) {
          passwords.put(role, secrets.resolve(config.password(role)));
        }
        if (issues(action) && loaded.containsKey(role)) {
          require(
              loaded.get(role).certificate().getNotAfter().toInstant()
                  .isAfter(clock.instant().plus(RENEW_BEFORE)),
              "Authority cannot cover the renewal window for " + role.argument()
                  + "; coordinate rollover first");
        }
      }
      WalletTrustAnchors anchors =
          selected.contains(WalletRole.TRUST_SOURCE) && loaded.size() == selected.size()
              ? anchors(config, authorities, before)
              : null;
      if (operation == Operation.VERIFY) {
        require(current != null, "No committed generation");
        verify(config, selected, loaded, anchors, before, passwords);
        return report(config, current, actions);
      }
      try (var lock = store.lock()) {
        require(lock.lock().isValid(), "Cannot acquire wallet state lock");
        var latest = store.current();
        require(
            java.util.Objects.equals(current == null ? null : current.generation(),
                latest == null ? null : latest.generation()),
            "Another generation was published; retry this operation");
        if (current != null && actions.values().stream().allMatch("REUSE"::equals)
            && !publicationChanged) {
          verify(config, selected, loaded, anchors, before, passwords);
          return report(config, current, actions);
        }
        try (var staging = store.begin(current)) {
          var layout = new EcosystemLayout(staging.state(), staging.bundle());
          var states = new EnumMap<WalletRole, RoleState>(WalletRole.class);
          states.putAll(previous);
          for (WalletRole role : selected) {
            var ca = loaded.get(role);
            if (ca == null) {
              ca = authorities.create(role, layout);
              loaded.put(role, ca);
            }
            pins.put(role, ArtifactStore.digest(ca.certificate().getEncoded()));
            authorities.publish(role, ca, layout);
          }
          if (selected.contains(WalletRole.TRUST_SOURCE)) {
            anchors = anchors(config, authorities, layout);
          }
          for (WalletRole role : selected) {
            String action = actions.get(role);
            var ca = loaded.get(role);
            if (!action.equals("REUSE")) {
              boolean issue = issues(action);
              boolean rotate = action.equals("ROTATE");
              switch (role) {
                case PID_ISSUER -> {
                  PidIssuerFlow.provision(config, ca, layout, clock,
                      passwords.get(role), issue, rotate);
                }
                case WALLET_PROVIDER -> {
                  WalletProviderFlow.provision(config, ca, layout, clock,
                      passwords.get(role), rotate);
                }
                case VERIFIER_ACCESS -> {
                  VerifierFlow.access(config, ca, layout, clock, passwords.get(role), rotate);
                }
                case VERIFIER_REGISTRATION -> {
                  VerifierFlow.registration(config, ca, layout, clock,
                      passwords.get(role), issue, rotate);
                }
                case TRUST_SOURCE -> {
                  TrustSourceFlow.provision(config, ca, anchors, layout, clock,
                      passwords.get(role), issue, rotate);
                }
                default -> throw new IllegalStateException("Unsupported wallet role: " + role);
              }
              var certificate = new IdentityStores(clock).publicCertificate(role, ca, layout);
              Instant documentExpiry = switch (role) {
                case PID_ISSUER -> RegistrationDocuments.expiresAt(layout.pidRegistration());
                case VERIFIER_REGISTRATION -> {
                  yield RegistrationDocuments.expiresAt(layout.verifierRegistration());
                }
                case TRUST_SOURCE -> TrustSourceFlow.documentsExpiry(layout);
                default -> null;
              };
              require(
                  documentExpiry == null
                      || documentExpiry.isAfter(clock.instant().plus(RENEW_BEFORE)),
                  "Signing certificate or document lifetime cannot cover the renewal window for "
                      + role.argument());
              states.put(role,
                  new RoleState(digest(config, role),
                      certificate.getNotAfter().toInstant().toString(),
                      documentExpiry == null ? null : documentExpiry.toString()));
            }
          }
          verify(config, selected, loaded, anchors, layout, passwords);
          var manifest = new Manifest(2, workflow, config.environment(), staging.generation(),
              clock.instant().toString(),
              states, pins, ArtifactStore.hashes(staging.bundle()),
              ArtifactStore.hashes(staging.state()));
          Path bundle = staging.commit(manifest);
          return new ProvisioningReport(config.environment(), staging.generation(), bundle,
              actions);
        }
      }
    } catch (Exception e) {
      if (e instanceof PkiConfigurationException exception) {
        throw exception;
      }
      throw new PkiConfigurationException(
          "Wallet provisioning failed; previous generation remains current: " + e.getMessage(), e);
    } finally {
      passwords.values().forEach(p -> Arrays.fill(p, '\0'));
    }
  }

  private void verify(PkiConfiguration config, EnumSet<WalletRole> selected,
      Map<WalletRole, CertificateAuthority> authorities, WalletTrustAnchors anchors,
      EcosystemLayout layout,
      Map<WalletRole, char[]> passwords) throws Exception {
    var stores = new IdentityStores(clock);
    var documents = new RegistrationDocuments(clock);
    var roots = new AuthorityStore(config, clock);
    for (WalletRole role : selected) {
      var ca = authorities.get(role);
      roots.verifyPublished(role, ca, layout);
      var certificate = stores.publicCertificate(role, ca, layout);
      if (passwords.containsKey(role)) {
        stores.verify(role, ca, layout, passwords.get(role));
      }
      switch (role) {
        case PID_ISSUER -> {
          documents.verifyPid(config.pidIssuer().registration(), certificate, layout);
        }
        case VERIFIER_REGISTRATION -> {
          documents.verifyVerifier(config.verifier().registration().registration(),
              config.organization(), certificate, ca, layout);
        }
        case TRUST_SOURCE -> {
          TrustSourceFlow.verify(config, anchors, certificate, layout, clock);
        }
        default -> {
        }
      }
    }
  }

  private WalletTrustAnchors anchors(PkiConfiguration config, AuthorityStore store,
      EcosystemLayout layout) {
    var a = config.trustSource().lote().trustedAuthorities();
    return new WalletTrustAnchors(
        store.publicCertificate(WalletRole.PID_ISSUER, layout, a.pidIssuer().certificateFile()),
        store.publicCertificate(WalletRole.WALLET_PROVIDER, layout,
            a.walletProvider().certificateFile()),
        store.publicCertificate(WalletRole.VERIFIER_ACCESS, layout,
            a.verifierAccess().certificateFile()),
        store.publicCertificate(WalletRole.VERIFIER_REGISTRATION, layout,
            a.verifierRegistration().certificateFile()));
  }

  private boolean due(String end) {
    return !Instant.parse(end).isAfter(clock.instant().plus(RENEW_BEFORE));
  }

  private static boolean issues(String action) {
    return action.equals("CREATE") || action.equals("RENEW") || action.equals("ROTATE");
  }

  private static String digest(PkiConfiguration config, WalletRole role)
      throws java.io.IOException {
    var publicInputs = new java.util.TreeMap<String, String>();
    if (role == WalletRole.TRUST_SOURCE) {
      var a = config.trustSource().lote().trustedAuthorities();
      var entries = Map.of(WalletRole.PID_ISSUER, a.pidIssuer(), WalletRole.WALLET_PROVIDER,
          a.walletProvider(),
          WalletRole.VERIFIER_ACCESS, a.verifierAccess(), WalletRole.VERIFIER_REGISTRATION,
          a.verifierRegistration());
      for (var entry : entries.entrySet()) {
        String file = entry.getValue().certificateFile();
        if (file == null && config.configuredRoles().contains(entry.getKey())) {
          file = config.authority(entry.getKey()).certificateFile();
        }
        if (file != null) {
          publicInputs.put(entry.getKey().name(),
              ArtifactStore.digest(Files.readAllBytes(Path.of(file))));
        }
      }
    }
    return ArtifactStore.digest(List.of(config.organization(), config.publicationBaseUrl(),
        config.settings(role), publicInputs));
  }

  private static ProvisioningReport report(PkiConfiguration config, Snapshot snapshot,
      Map<WalletRole, String> actions) {
    return new ProvisioningReport(config.environment(), snapshot.generation(), snapshot.bundle(),
        actions);
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new PkiConfigurationException(message);
    }
  }
}
