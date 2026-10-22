// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.nio.file.Path;
import se.digg.wallet.pki.domain.WalletRole;

/** Fixed paths used by the wallet consumers in both deployment workflows. */
public record EcosystemLayout(Path state, Path output) {
  public Path authority(WalletRole role) {
    return state.resolve("authorities/" + role.directory());
  }

  public Path certificate(WalletRole role) {
    return state.resolve("identities/" + role.argument() + ".pem");
  }

  public Path publication(WalletRole role) {
    return output.resolve("public/trust-source/" + role.directory());
  }

  public Path keystore(WalletRole role) {
    return switch (role) {
      case PID_ISSUER -> pidKeystore();
      case WALLET_PROVIDER -> walletKeystore();
      case VERIFIER_ACCESS -> verifierAccessKeystore();
      case VERIFIER_REGISTRATION -> verifierRegistrationKeystore();
      case TRUST_SOURCE -> trustSignerKeystore();
    };
  }

  public Path pidKeystore() {
    return output.resolve("private/certificates/issuer/pid_issuer.p12");
  }

  public Path walletKeystore() {
    return output.resolve("private/certificates/wallet-provider/wallet_provider.p12");
  }

  public Path verifierAccessKeystore() {
    return output.resolve(
        "private/certificates/verifier-access-certificate/verifier-access-certificate.p12");
  }

  public Path verifierRegistrationKeystore() {
    return output.resolve(
        "private/certificates/verifier-registration-certificate/"
            + "verifier-registration-certificate.p12");
  }

  public Path trustSignerKeystore() {
    return output.resolve("private/certificates/trust-list-signer/trust_source.p12");
  }

  public Path pidRegistration() {
    return output.resolve("public/pid-issuer/issuer_wrprc.jwt");
  }

  public Path verifierRegistration() {
    return output.resolve(
        "public/certificates/verifier-registration-certificate/registration_certificate.jwt");
  }

  public Path verifierEnvironment() {
    return verifierRegistration().resolveSibling("registration_certificate.env");
  }

  public Path trustSignerCertificate() {
    return output.resolve("public/certificates/trust-list-signer/trust_source_cert.pem");
  }

  public Path lote() {
    return output.resolve("public/trust-source/signed/trusted-entities.json");
  }

  public Path statusList() {
    return output.resolve("public/trust-source/signed/status-list.jwt");
  }
}
