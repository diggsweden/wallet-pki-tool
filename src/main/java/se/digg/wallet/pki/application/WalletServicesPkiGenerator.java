// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.io.PrintWriter;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;

/** Generates PKI material for the PID issuer, wallet provider, verifier and trust source. */
public final class WalletServicesPkiGenerator {
  private final PidIssuerFlow pidIssuer;
  private final WalletProviderFlow walletProvider;
  private final VerifierFlow verifier;
  private final TrustSourceFlow trustSource;

  public WalletServicesPkiGenerator(SecretResolver secrets) {
    pidIssuer = new PidIssuerFlow(secrets);
    walletProvider = new WalletProviderFlow(secrets);
    verifier = new VerifierFlow(secrets);
    trustSource = new TrustSourceFlow(secrets);
  }

  public void generate(PkiConfiguration config, PrintWriter out) {
    PidIssuerFlow.requireConfiguration(config);
    WalletProviderFlow.requireConfiguration(config);
    VerifierFlow.requireAccessConfiguration(config);
    VerifierFlow.requireRegistrationConfiguration(config);
    TrustSourceFlow.requireConfiguration(config);

    try (var pidIssuerInputs = pidIssuer.loadInputs(config);
        var walletProviderInputs = walletProvider.loadInputs(config);
        var verifierAccessInputs = verifier.loadAccessInputs(config);
        var verifierRegistrationInputs = verifier.loadRegistrationInputs(config);
        var trustSourceInputs = trustSource.loadInputs(config)) {
      var trustedAuthorities = trustSource.loadTrustedAuthorities(config);

      pidIssuer.generate(config, pidIssuerInputs, out);
      walletProvider.generate(config, walletProviderInputs, out);
      verifier.generateAccess(config, verifierAccessInputs, out);
      verifier.generateRegistration(config, verifierRegistrationInputs, out);
      trustSource.generate(config, trustSourceInputs, trustedAuthorities, out);
    }
  }
}
