// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.infrastructure;

import java.nio.file.Path;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.domain.AuthorityRole;

/** Artifact paths are a fixed contract with the ecosystem consumers. */
public record EcosystemLayout(Path state, Path output) {
  public EcosystemLayout(PkiConfiguration config) {
    this(Path.of(config.stateDirectory()), Path.of(config.outputDirectory()));
  }

  public Path authority(AuthorityRole role) {
    return state.resolve("authorities").resolve(role.directory());
  }

  public Path publication(AuthorityRole role) {
    return output.resolve("trust-source").resolve(role.directory());
  }

  public Path pidKeystore() {
    return output.resolve("certificates/issuer/pid_issuer.p12");
  }

  public Path pidRegistration() {
    return output.resolve("pid-issuer/issuer_wrprc.jwt");
  }

  public Path walletKeystore() {
    return output.resolve("certificates/wallet-provider/wallet_provider.p12");
  }

  public Path verifierAccessKeystore() {
    return output
        .resolve("certificates/verifier-access-certificate/verifier-access-certificate.p12");
  }

  public Path verifierRegistrationKeystore() {
    return output.resolve(
        "certificates/verifier-registration-certificate/verifier-registration-certificate.p12");
  }

  public Path verifierRegistration() {
    return output
        .resolve("certificates/verifier-registration-certificate/registration_certificate.jwt");
  }

  public Path verifierEnvironment() {
    return output
        .resolve("certificates/verifier-registration-certificate/registration_certificate.env");
  }

  public Path trustSignerKeystore() {
    return output.resolve("certificates/trust-list-signer/trust_source.p12");
  }

  public Path trustSignerCertificate() {
    return output.resolve("certificates/trust-list-signer/trust_source_cert.pem");
  }

  public Path lote() {
    return output.resolve("trust-source/signed/trusted-entities.json");
  }

  public Path statusList() {
    return output.resolve("trust-source/signed/status-list.jwt");
  }
}
