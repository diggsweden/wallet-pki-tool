// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.io.PrintWriter;
import java.nio.file.Path;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.config.WalletAttestationIssuerConfig;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.domain.Checks;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.infrastructure.IdentityStores;

/** Wallet attestation signing identity and the wallet_attestation_issuer keystore entry. */
public final class WalletAttestationIssuerFlow {
  private final SecretResolver secrets;

  public WalletAttestationIssuerFlow(SecretResolver secrets) {
    this.secrets = secrets;
  }

  static WalletAttestationIssuerConfig requireConfiguration(PkiConfiguration config) {
    return Checks.required(config.walletAttestationIssuer(), "walletAttestationIssuer");
  }

  ServicePkiInputs loadInputs(PkiConfiguration config) {
    var walletAttestationIssuer = requireConfiguration(config);
    return ServicePkiInputs.load(config, AuthorityRole.WALLET_ATTESTATION_ISSUER,
        walletAttestationIssuer.keystorePassword(), secrets);
  }

  public void generate(PkiConfiguration config, PrintWriter out) {
    try (var inputs = loadInputs(config)) {
      generate(config, inputs, out);
    }
  }

  void generate(PkiConfiguration config, ServicePkiInputs inputs, PrintWriter out) {
    var walletAttestationIssuer = config.walletAttestationIssuer();
    var authority = inputs.authority();
    var certificates = new CertificateProfileIssuer(config.caDistribution().baseUrl());
    var key = new EcKeyGenerator().generateKeyPair();
    var certificate = certificates.issueWalletSigningCertificate(
        walletAttestationIssuer.signing().subject(config.organization()), key.getPublic(),
        authority);
    new IdentityStores().write(
        Path.of(config.outputDirectory()).resolve(walletAttestationIssuer.keystoreFile()),
        "wallet_attestation_issuer",
        new SigningIdentity(key, certificate), authority, inputs.keystorePassword());
    inputs.publishAuthority();
    out.println("Generated: wallet-attestation-issuer (new keys; selected files replaced)");
  }
}
