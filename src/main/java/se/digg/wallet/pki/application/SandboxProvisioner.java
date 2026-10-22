// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;

/** Provisions configured sandbox participants using supplied authorities and existing CRLs. */
public final class SandboxProvisioner {
  private final SecretResolver secrets;
  private final Clock clock;

  public SandboxProvisioner(SecretResolver secrets, Clock clock) {
    this.secrets = secrets;
    this.clock = clock;
  }

  public ProvisioningReport run(Path source, Operation operation, List<String> roles) {
    var config = new ConfigurationLoader().load(source);
    for (var role : config.configuredRoles()) {
      if (config.authority(role)
          .source() != se.digg.wallet.pki.config.AuthorityConfig.Source.EXISTING) {
        throw new IllegalArgumentException(
            "Sandbox requires existing certificate, private key and CRL for " + role.argument());
      }
    }
    return new WalletProvisioner(secrets, clock).run(config, "sandbox", operation, roles);
  }
}
