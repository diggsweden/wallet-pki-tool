// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import se.digg.wallet.pki.config.WalletProviderConfig;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.crypto.EcKeyGenerator;
import se.digg.wallet.pki.domain.Organization;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.infrastructure.EcosystemLayout;
import se.digg.wallet.pki.infrastructure.IdentityStores;

/** Wallet attestation signing identity and the wallet_provider keystore entry. */
public final class WalletProviderFlow {
  private final Organization organization;
  private final CertificateProfileIssuer certificates;
  private final EcosystemLayout layout;

  public WalletProviderFlow(Organization organization, CertificateProfileIssuer certificates, EcosystemLayout layout) {
    this.organization = organization;
    this.certificates = certificates;
    this.layout = layout;
  }

  public void generate(WalletProviderConfig config, CertificateAuthority authority, char[] password) {
    var key = new EcKeyGenerator().generateKeyPair();
    var certificate = certificates.issueWalletSigningCertificate(
        config.signing().subject(organization), key.getPublic(), authority);
    new IdentityStores().write(layout.walletKeystore(), "wallet_provider",
        new SigningIdentity(key, certificate), authority, password);
  }
}
