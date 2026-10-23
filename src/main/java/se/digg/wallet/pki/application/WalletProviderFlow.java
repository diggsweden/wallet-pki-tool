// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.time.Clock;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.crypto.CertificateProfileIssuer;
import se.digg.wallet.pki.domain.SigningIdentity;
import se.digg.wallet.pki.domain.WalletRole;
import se.digg.wallet.pki.infrastructure.ArtifactLayout;
import se.digg.wallet.pki.infrastructure.IdentityStores;

/** Owns the wallet attestation signing certificate and wallet_provider keystore entry. */
final class WalletProviderFlow {
  static void generate(PkiConfiguration config, CertificateAuthority ca, ArtifactLayout layout,
      Clock clock, char[] password) throws Exception {
    var stores = new IdentityStores(clock);
    var key = new se.digg.wallet.pki.crypto.EcKeyGenerator().generateKeyPair();
    var issuer = new CertificateProfileIssuer(new java.security.SecureRandom(),
        config.publicationBaseUrl(), clock);
    var certificate = issuer.issueWalletSigningCertificate(
        config.walletProvider().signing().subject(config.organization()), key.getPublic(), ca);
    stores.write(WalletRole.WALLET_PROVIDER, new SigningIdentity(key, certificate), ca, layout,
        password);
  }
}
