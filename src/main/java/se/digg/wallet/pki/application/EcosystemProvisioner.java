// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.io.PrintWriter;
import java.util.EnumSet;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.domain.AuthorityRole;

/** Explicit bulk operation; all role configuration, secrets and authorities are preflighted. */
public final class EcosystemProvisioner {
  private final RoleProvisioner roles;

  public EcosystemProvisioner(SecretResolver secrets) {
    roles = new RoleProvisioner(secrets);
  }

  public void generate(PkiConfiguration config, PrintWriter out) {
    try (var inputs = roles.prepare(config, EnumSet.allOf(AuthorityRole.class))) {
      roles.generatePidIssuer(config, inputs, out);
      roles.generateWalletProvider(config, inputs, out);
      roles.generateVerifierAccess(config, inputs, out);
      roles.generateVerifierRegistration(config, inputs, out);
      roles.generateTrustSource(config, inputs, out);
      roles.publish(config, inputs);
    }
  }
}
