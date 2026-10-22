// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import se.digg.wallet.pki.config.PasswordSource;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.WalletTrustAnchors;
import se.digg.wallet.pki.infrastructure.AuthorityStore;
import se.digg.wallet.pki.infrastructure.EcosystemLayout;
import se.digg.wallet.pki.infrastructure.IdentityStores;

/**
 * Named wallet operations in dependency order; all required inputs are checked before output
 * changes.
 */
public final class EcosystemProvisioner {
  private final SecretResolver secrets;

  public EcosystemProvisioner(SecretResolver secrets) {
    this.secrets = secrets;
  }

  public void initializeAuthorities(PkiConfiguration config, PrintWriter out) {
    var authorities = new AuthorityStore(config);
    for (var role : AuthorityRole.values()) {
      authorities.initialize(role);
      out.println("Authority ready: " + role.directory());
    }
  }

  public void generate(PkiConfiguration config, List<String> arguments, PrintWriter out) {
    var selected = GenerationTarget.select(arguments);
    var layout = new EcosystemLayout(config);
    var authorities = new AuthorityStore(config);
    var certificates =
        new CertificateProfileIssuer(new SecureRandom(), config.trustSource().publicationBaseUrl());
    var passwords = new EnumMap<GenerationTarget, char[]>(GenerationTarget.class);
    try {
      for (var target : selected) {
        PasswordSource source = passwordSource(config, target);
        if (source != null)
          passwords.put(target, secrets.resolve(source));
      }
      boolean needsSigner = selected.contains(GenerationTarget.LOTE)
          || selected.contains(GenerationTarget.STATUS_LIST);
      if (needsSigner && !selected.contains(GenerationTarget.TRUST_SOURCE)) {
        passwords.put(GenerationTarget.TRUST_SOURCE,
            secrets.resolve(config.trustSource().signer().keystorePassword()));
      }
      var loaded = loadRequiredAuthorities(authorities, selected);
      WalletTrustAnchors anchors =
          selected.contains(GenerationTarget.LOTE) ? new WalletTrustAnchors(
              authorities.loadPublic(AuthorityRole.PID_ISSUER),
              authorities.loadPublic(AuthorityRole.WALLET_PROVIDER),
              authorities.loadPublic(AuthorityRole.VERIFIER_ACCESS),
              authorities.loadPublic(AuthorityRole.VERIFIER_REGISTRATION)) : null;
      SigningIdentity signer = needsSigner && !selected.contains(GenerationTarget.TRUST_SOURCE)
          ? new IdentityStores().loadTrustSigner(layout.trustSignerKeystore(),
              passwords.get(GenerationTarget.TRUST_SOURCE),
              authorities.loadPublic(AuthorityRole.TRUST_SOURCE))
          : null;

      var verifier = new VerifierFlow(config.organization(), certificates, layout);
      var trustSource = new TrustSourceFlow(config.organization(), layout);
      if (selected.contains(GenerationTarget.PID_ISSUER)) {
        new PidIssuerFlow(config.organization(), certificates, layout).generate(config.pidIssuer(),
            loaded.get(AuthorityRole.PID_ISSUER), passwords.get(GenerationTarget.PID_ISSUER));
      }
      if (selected.contains(GenerationTarget.WALLET_PROVIDER)) {
        new WalletProviderFlow(config.organization(), certificates, layout).generate(config.walletProvider(),
            loaded.get(AuthorityRole.WALLET_PROVIDER), passwords.get(GenerationTarget.WALLET_PROVIDER));
      }
      if (selected.contains(GenerationTarget.VERIFIER_ACCESS)) {
        verifier.generateAccess(config.verifier().access(),
            loaded.get(AuthorityRole.VERIFIER_ACCESS),
            passwords.get(GenerationTarget.VERIFIER_ACCESS));
      }
      if (selected.contains(GenerationTarget.VERIFIER_REGISTRATION)) {
        verifier.generateRegistration(config.verifier().registration(),
            loaded.get(AuthorityRole.VERIFIER_REGISTRATION),
            passwords.get(GenerationTarget.VERIFIER_REGISTRATION));
      }
      if (selected.contains(GenerationTarget.TRUST_SOURCE)) {
        signer = trustSource.generateSigner(config.trustSource().signer(),
            loaded.get(AuthorityRole.TRUST_SOURCE),
            certificates, passwords.get(GenerationTarget.TRUST_SOURCE));
      }
      if (selected.contains(GenerationTarget.LOTE))
        trustSource.generateLote(config.trustSource(), anchors, signer);
      if (selected.contains(GenerationTarget.STATUS_LIST))
        trustSource.generateStatusList(config.trustSource().statusList(), signer);
      for (var entry : loaded.entrySet())
        authorities.publish(entry.getKey(), entry.getValue());
      selected.forEach(target -> out.println("Generated: " + target));
    } finally {
      passwords.values().forEach(password -> Arrays.fill(password, '\0'));
    }
  }

  private EnumMap<AuthorityRole, CertificateAuthority> loadRequiredAuthorities(AuthorityStore store,
      EnumSet<GenerationTarget> selected) {
    var loaded = new EnumMap<AuthorityRole, CertificateAuthority>(AuthorityRole.class);
    for (var target : selected) {
      AuthorityRole role = switch (target) {
        case PID_ISSUER -> AuthorityRole.PID_ISSUER;
        case WALLET_PROVIDER -> AuthorityRole.WALLET_PROVIDER;
        case VERIFIER_ACCESS -> AuthorityRole.VERIFIER_ACCESS;
        case VERIFIER_REGISTRATION -> AuthorityRole.VERIFIER_REGISTRATION;
        case TRUST_SOURCE -> AuthorityRole.TRUST_SOURCE;
        case LOTE, STATUS_LIST -> null;
      };
      if (role != null)
        loaded.put(role, store.load(role));
    }
    return loaded;
  }

  private PasswordSource passwordSource(PkiConfiguration config, GenerationTarget target) {
    return switch (target) {
      case PID_ISSUER -> config.pidIssuer().keystorePassword();
      case WALLET_PROVIDER -> config.walletProvider().keystorePassword();
      case VERIFIER_ACCESS -> config.verifier().access().keystorePassword();
      case VERIFIER_REGISTRATION -> config.verifier().registration().keystorePassword();
      case TRUST_SOURCE -> config.trustSource().signer().keystorePassword();
      case LOTE, STATUS_LIST -> null;
    };
  }
}
