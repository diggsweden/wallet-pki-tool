// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.io.PrintWriter;
import java.util.Set;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.infrastructure.AuthorityStore;

/** Only authority initialization may create missing managed roots. No passwords are needed. */
public final class AuthorityProvisioner {
  public void initialize(PkiConfiguration config, Set<AuthorityRole> roles, PrintWriter out) {
    var store = new AuthorityStore(config);
    for (var role : roles) {
      store.validateExisting(role);
    }
    for (var role : AuthorityRole.values()) {
      if (roles.contains(role)) {
        store.initialize(role);
        out.println("Authority ready: " + role.directory());
      }
    }
  }
}
