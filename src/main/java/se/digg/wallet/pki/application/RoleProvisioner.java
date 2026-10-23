// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import se.digg.wallet.pki.config.PasswordSource;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.config.TrustSourceConfig;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.WalletTrustAnchors;
import se.digg.wallet.pki.infrastructure.AuthorityStore;
import se.digg.wallet.pki.infrastructure.IdentityStores;

/** Named application operations. Generation never initializes authorities. */
public final class RoleProvisioner {
  private final SecretResolver secrets;

  public RoleProvisioner(SecretResolver secrets) {
    this.secrets = secrets;
  }

  public void generatePidIssuer(PkiConfiguration config, PrintWriter out) {
    try (var inputs = prepare(config, EnumSet.of(AuthorityRole.PID_ISSUER))) {
      generatePidIssuer(config, inputs, out);
      publish(config, inputs);
    }
  }

  public void generateWalletProvider(PkiConfiguration config, PrintWriter out) {
    try (var inputs = prepare(config, EnumSet.of(AuthorityRole.WALLET_PROVIDER))) {
      generateWalletProvider(config, inputs, out);
      publish(config, inputs);
    }
  }

  public void generateVerifierAccess(PkiConfiguration config, PrintWriter out) {
    try (var inputs = prepare(config, EnumSet.of(AuthorityRole.VERIFIER_ACCESS))) {
      generateVerifierAccess(config, inputs, out);
      publish(config, inputs);
    }
  }

  public void generateVerifierRegistration(PkiConfiguration config, PrintWriter out) {
    try (var inputs = prepare(config, EnumSet.of(AuthorityRole.VERIFIER_REGISTRATION))) {
      generateVerifierRegistration(config, inputs, out);
      publish(config, inputs);
    }
  }

  public void generateTrustSource(PkiConfiguration config, PrintWriter out) {
    try (var inputs = prepare(config, EnumSet.of(AuthorityRole.TRUST_SOURCE))) {
      generateTrustSource(config, inputs, out);
      publish(config, inputs);
    }
  }

  public void generateLote(PkiConfiguration config, PrintWriter out) {
    var trust = trustSource(config);
    Checks.required(trust.lote(), "trustSource.lote");
    var anchors = trustAnchors(config);
    char[] password = secrets.resolve(trust.signer().keystorePassword());
    try {
      var signer = existingSigner(config, password);
      new TrustSourceFlow(config.organization(), Path.of(config.outputDirectory()))
          .generateLote(trust, anchors, signer);
      out.println("Generated: lote (existing signer retained)");
    } finally {
      Arrays.fill(password, '\0');
    }
  }

  public void generateStatusList(PkiConfiguration config, PrintWriter out) {
    var trust = trustSource(config);
    Checks.required(trust.statusList(), "trustSource.statusList");
    char[] password = secrets.resolve(trust.signer().keystorePassword());
    try {
      var signer = existingSigner(config, password);
      new TrustSourceFlow(config.organization(), Path.of(config.outputDirectory()))
          .generateStatusList(trust.statusList(), signer);
      out.println("Generated: status-list (existing signer retained)");
    } finally {
      Arrays.fill(password, '\0');
    }
  }

  Prepared prepare(PkiConfiguration config, EnumSet<AuthorityRole> roles) {
    var sources = new EnumMap<AuthorityRole, PasswordSource>(AuthorityRole.class);
    for (var role : roles) {
      sources.put(role, passwordSource(config, role));
    }
    var inputs = new Prepared();
    try {
      for (var role : roles) {
        inputs.passwords.put(role, secrets.resolve(sources.get(role)));
      }
      var store = new AuthorityStore(config);
      for (var role : roles) {
        inputs.authorities.put(role, store.load(role));
      }
      if (roles.contains(AuthorityRole.TRUST_SOURCE)) {
        inputs.anchors = trustAnchors(config);
      }
      return inputs;
    } catch (RuntimeException e) {
      inputs.close();
      throw e;
    }
  }

  void generatePidIssuer(PkiConfiguration config, Prepared inputs, PrintWriter out) {
    new PidIssuerFlow(config.organization(), certificates(config),
        Path.of(config.outputDirectory()))
        .generate(config.pidIssuer(), inputs.authorities.get(AuthorityRole.PID_ISSUER),
            inputs.passwords.get(AuthorityRole.PID_ISSUER));
    out.println("Generated: pid-issuer (new keys; selected files replaced)");
  }

  void generateWalletProvider(PkiConfiguration config, Prepared inputs, PrintWriter out) {
    new WalletProviderFlow(config.organization(), certificates(config),
        Path.of(config.outputDirectory())).generate(config.walletProvider(),
            inputs.authorities.get(AuthorityRole.WALLET_PROVIDER),
            inputs.passwords.get(AuthorityRole.WALLET_PROVIDER));
    out.println("Generated: wallet-provider (new keys; selected files replaced)");
  }

  void generateVerifierAccess(PkiConfiguration config, Prepared inputs, PrintWriter out) {
    new VerifierFlow(config.organization(), certificates(config), Path.of(config.outputDirectory()))
        .generateAccess(config.verifier().access(),
            inputs.authorities.get(AuthorityRole.VERIFIER_ACCESS),
            inputs.passwords.get(AuthorityRole.VERIFIER_ACCESS));
    out.println("Generated: verifier-access (new keys; selected files replaced)");
  }

  void generateVerifierRegistration(PkiConfiguration config, Prepared inputs, PrintWriter out) {
    new VerifierFlow(config.organization(), certificates(config), Path.of(config.outputDirectory()))
        .generateRegistration(config.verifier().registration(),
            inputs.authorities.get(AuthorityRole.VERIFIER_REGISTRATION),
            inputs.passwords.get(AuthorityRole.VERIFIER_REGISTRATION));
    out.println("Generated: verifier-registration (new keys; selected files replaced)");
  }

  void generateTrustSource(PkiConfiguration config, Prepared inputs, PrintWriter out) {
    var flow = new TrustSourceFlow(config.organization(), Path.of(config.outputDirectory()));
    var signer = flow.generateSigner(config.trustSource().signer(),
        inputs.authorities.get(AuthorityRole.TRUST_SOURCE), certificates(config),
        inputs.passwords.get(AuthorityRole.TRUST_SOURCE));
    flow.generateLote(config.trustSource(), inputs.anchors, signer);
    flow.generateStatusList(config.trustSource().statusList(), signer);
    out.println("Generated: trust-source (new signer; lote and status-list rebuilt)");
  }

  void publish(PkiConfiguration config, Prepared inputs) {
    var store = new AuthorityStore(config);
    inputs.authorities.forEach(store::publish);
  }

  private CertificateProfileIssuer certificates(PkiConfiguration config) {
    return new CertificateProfileIssuer(new SecureRandom(), config.publication().baseUrl());
  }

  private PasswordSource passwordSource(PkiConfiguration config, AuthorityRole role) {
    return switch (role) {
      case PID_ISSUER -> Checks.required(config.pidIssuer(), "pidIssuer").keystorePassword();
      case WALLET_PROVIDER -> Checks.required(config.walletProvider(), "walletProvider")
          .keystorePassword();
      case VERIFIER_ACCESS -> Checks.required(
          Checks.required(config.verifier(), "verifier").access(), "verifier.access")
          .keystorePassword();
      case VERIFIER_REGISTRATION -> Checks.required(
          Checks.required(config.verifier(), "verifier").registration(), "verifier.registration")
          .keystorePassword();
      case TRUST_SOURCE -> {
        var trust = trustSource(config);
        Checks.required(trust.lote(), "trustSource.lote");
        Checks.required(trust.statusList(), "trustSource.statusList");
        Checks.text(trust.signer().commonName(), "trustSource.signer.commonName");
        Checks.relativePath(trust.signer().certificateFile(), "trustSource.signer.certificateFile");
        yield trust.signer().keystorePassword();
      }
    };
  }

  private TrustSourceConfig trustSource(PkiConfiguration config) {
    var trust = Checks.required(config.trustSource(), "trustSource");
    Checks.required(trust.signer(), "trustSource.signer");
    return trust;
  }

  private SigningIdentity existingSigner(PkiConfiguration config, char[] password) {
    return new IdentityStores().loadTrustSigner(
        Path.of(config.outputDirectory()).resolve(config.trustSource().signer().keystoreFile()),
        password, new AuthorityStore(config).loadPublic(AuthorityRole.TRUST_SOURCE));
  }

  private WalletTrustAnchors trustAnchors(PkiConfiguration config) {
    var store = new AuthorityStore(config);
    return new WalletTrustAnchors(store.loadPublic(AuthorityRole.PID_ISSUER),
        store.loadPublic(AuthorityRole.WALLET_PROVIDER),
        store.loadPublic(AuthorityRole.VERIFIER_ACCESS),
        store.loadPublic(AuthorityRole.VERIFIER_REGISTRATION));
  }

  static final class Prepared implements AutoCloseable {
    private final EnumMap<AuthorityRole, char[]> passwords = new EnumMap<>(AuthorityRole.class);
    private final EnumMap<AuthorityRole, CertificateAuthority> authorities =
        new EnumMap<>(AuthorityRole.class);
    private WalletTrustAnchors anchors;

    @Override
    public void close() {
      passwords.values().forEach(password -> Arrays.fill(password, '\0'));
    }
  }
}
