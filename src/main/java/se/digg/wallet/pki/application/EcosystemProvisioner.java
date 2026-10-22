// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.SecretResolver;

/** Provisions the complete local ecosystem and may initialize development roots. */
public final class EcosystemProvisioner {
  private final SecretResolver secrets;
  private final Clock clock;

  public EcosystemProvisioner(SecretResolver secrets, Clock clock) {
    this.secrets = secrets;
    this.clock = clock;
  }

  public ProvisioningReport run(Path source, Operation operation, List<String> roles) {
    var config = new ConfigurationLoader().load(source);
    if (!config.configuredRoles()
        .equals(java.util.EnumSet.allOf(se.digg.wallet.pki.domain.WalletRole.class))) {
      throw new IllegalArgumentException(
          "Ecosystem requires PID issuer, wallet provider, "
              + "verifier access, verifier registration and trust source");
    }
    return new WalletProvisioner(secrets, clock).run(config, "ecosystem", operation, roles);
  }
}
