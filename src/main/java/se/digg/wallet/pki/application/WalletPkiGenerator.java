// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.nio.file.Path;
import java.time.Clock;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.PkiConfigurationException;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.domain.WalletRole;
import se.digg.wallet.pki.domain.WalletTrustAnchors;
import se.digg.wallet.pki.infrastructure.ArtifactLayout;
import se.digg.wallet.pki.infrastructure.AuthorityStore;
import se.digg.wallet.pki.infrastructure.IdentityStores;
import se.digg.wallet.pki.infrastructure.OutputDirectory;
import se.digg.wallet.pki.trustlist.RegistrationDocuments;

/** Initializes authorities explicitly and generates the selected wallet artifacts on request. */
public final class WalletPkiGenerator {
  private final SecretResolver secrets;
  private final Clock clock;

  public WalletPkiGenerator(SecretResolver secrets, Clock clock) {
    this.secrets = secrets;
    this.clock = clock;
  }

  public Set<WalletRole> initializeAuthorities(Path source, List<String> arguments) {
    var config = new ConfigurationLoader().load(source);
    var roles = WalletRole.select(arguments, config.configuredRoles());
    try {
      new AuthorityStore(config, clock).initialize(roles);
      return Set.copyOf(roles);
    } catch (Exception e) {
      throw new PkiConfigurationException("Authority initialization failed: " + e.getMessage(), e);
    }
  }

  public GeneratedArtifacts generate(Path source, List<String> arguments, Path output) {
    PkiConfiguration config = new ConfigurationLoader().load(source);
    var roles = WalletRole.select(arguments, config.configuredRoles());
    Path destination =
        (output == null ? Path.of(config.outputDirectory()) : output).toAbsolutePath().normalize();
    Path authoritiesPath = Path.of(config.authorityDirectory());
    if (destination.startsWith(authoritiesPath) || authoritiesPath.startsWith(destination)) {
      throw new PkiConfigurationException(
          "Authority and output directories must be separate and non-nested");
    }
    OutputDirectory.requireAbsent(destination);
    var passwords = new EnumMap<WalletRole, char[]>(WalletRole.class);
    try {
      var authorities = new AuthorityStore(config, clock);
      var loaded = new EnumMap<WalletRole, CertificateAuthority>(WalletRole.class);
      for (WalletRole role : roles) {
        loaded.put(role, authorities.load(role));
      }
      WalletTrustAnchors anchors =
          roles.contains(WalletRole.TRUST_SOURCE) ? anchors(config, authorities) : null;
      for (WalletRole role : roles) {
        passwords.put(role, secrets.resolve(config.password(role)));
      }
      try (var staging = new OutputDirectory(destination)) {
        var layout = new ArtifactLayout(staging.path());
        for (WalletRole role : roles) {
          var ca = loaded.get(role);
          authorities.publish(role, ca, layout);
          switch (role) {
            case PID_ISSUER -> {
              PidIssuerFlow.generate(config, ca, layout, clock, passwords.get(role));
            }
            case WALLET_PROVIDER -> {
              WalletProviderFlow.generate(config, ca, layout, clock, passwords.get(role));
            }
            case VERIFIER_ACCESS -> {
              VerifierFlow.access(config, ca, layout, clock, passwords.get(role));
            }
            case VERIFIER_REGISTRATION -> {
              VerifierFlow.registration(config, ca, layout, clock, passwords.get(role));
            }
            case TRUST_SOURCE -> {
              TrustSourceFlow.generate(config, ca, anchors, layout, clock, passwords.get(role));
            }
            default -> throw new IllegalStateException("Unsupported wallet role: " + role);
          }
        }
        validate(config, roles, loaded, anchors, layout, passwords);
        return new GeneratedArtifacts(staging.publish(), roles);
      }
    } catch (Exception e) {
      throw new PkiConfigurationException("Artifact generation failed: " + e.getMessage(), e);
    } finally {
      passwords.values().forEach(password -> Arrays.fill(password, '\0'));
    }
  }

  private void validate(PkiConfiguration config, EnumSet<WalletRole> roles,
      EnumMap<WalletRole, CertificateAuthority> authorities, WalletTrustAnchors anchors,
      ArtifactLayout layout, EnumMap<WalletRole, char[]> passwords) throws Exception {
    var stores = new IdentityStores(clock);
    var documents = new RegistrationDocuments(clock);
    var roots = new AuthorityStore(config, clock);
    for (WalletRole role : roles) {
      var ca = authorities.get(role);
      roots.verifyPublished(role, ca, layout);
      var certificate = stores.verify(role, ca, layout, passwords.get(role));
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

  private WalletTrustAnchors anchors(PkiConfiguration config, AuthorityStore store) {
    var a = config.trustSource().lote().trustedAuthorities();
    return new WalletTrustAnchors(
        store.publicCertificate(WalletRole.PID_ISSUER, a.pidIssuer().certificateFile()),
        store.publicCertificate(WalletRole.WALLET_PROVIDER, a.walletProvider().certificateFile()),
        store.publicCertificate(WalletRole.VERIFIER_ACCESS, a.verifierAccess().certificateFile()),
        store.publicCertificate(WalletRole.VERIFIER_REGISTRATION,
            a.verifierRegistration().certificateFile()));
  }
}
