// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.application;

import java.util.Arrays;
import se.digg.wallet.pki.config.PasswordSource;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.crypto.CertificateAuthority;
import se.digg.wallet.pki.domain.AuthorityRole;
import se.digg.wallet.pki.infrastructure.AuthorityStore;

/** An initialized service authority and keystore password, cleared when generation ends. */
final class ServicePkiInputs implements AutoCloseable {
  private final AuthorityStore authorities;
  private final AuthorityRole service;
  private final CertificateAuthority authority;
  private final char[] keystorePassword;

  private ServicePkiInputs(AuthorityStore authorities, AuthorityRole service,
      CertificateAuthority authority, char[] keystorePassword) {
    this.authorities = authorities;
    this.service = service;
    this.authority = authority;
    this.keystorePassword = keystorePassword;
  }

  static ServicePkiInputs load(PkiConfiguration config, AuthorityRole service,
      PasswordSource passwordSource, SecretResolver secrets) {
    char[] password = secrets.resolve(passwordSource);
    try {
      var authorities = new AuthorityStore(config);
      return new ServicePkiInputs(authorities, service, authorities.load(service), password);
    } catch (RuntimeException e) {
      Arrays.fill(password, '\0');
      throw e;
    }
  }

  CertificateAuthority authority() {
    return authority;
  }

  char[] keystorePassword() {
    return keystorePassword;
  }

  void publishAuthority() {
    authorities.publish(service, authority);
  }

  @Override
  public void close() {
    Arrays.fill(keystorePassword, '\0');
  }
}
