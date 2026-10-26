// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.security.SecureRandom;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.config.WalletProviderConfig;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.infrastructure.IdentityStores;

/** Wallet attestation signing identity and the wallet_provider keystore entry. */
public final class WalletProviderFlow {
  private final SecretResolver secrets;

  public WalletProviderFlow(SecretResolver secrets) {
    this.secrets = secrets;
  }

  public void generate(PkiConfiguration config, PrintWriter out) {
    try (var inputs = loadInputs(config)) {
      generate(config, inputs, out);
    }
  }

  static WalletProviderConfig requireConfiguration(PkiConfiguration config) {
    return Checks.required(config.walletProvider(), "walletProvider");
  }

  ServicePkiInputs loadInputs(PkiConfiguration config) {
    var walletProvider = requireConfiguration(config);
    return ServicePkiInputs.load(config, AuthorityRole.WALLET_PROVIDER,
        walletProvider.keystorePassword(), secrets);
  }

  void generate(PkiConfiguration config, ServicePkiInputs inputs, PrintWriter out) {
    var walletProvider = config.walletProvider();
    var authority = inputs.authority();
    var certificates =
        new CertificateProfileIssuer(new SecureRandom(), config.caDistribution().baseUrl());
    var key = new EcKeyGenerator().generateKeyPair();
    var certificate = certificates.issueWalletSigningCertificate(
        walletProvider.signing().subject(config.organization()), key.getPublic(), authority);
    new IdentityStores().write(
        Path.of(config.outputDirectory()).resolve(walletProvider.keystoreFile()), "wallet_provider",
        new SigningIdentity(key, certificate), authority, inputs.keystorePassword());
    inputs.publishAuthority();
    out.println("Generated: wallet-provider (new keys; selected files replaced)");
  }
}
