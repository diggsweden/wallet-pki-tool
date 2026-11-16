// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import se.digg.wallet.pki.config.VerifierConfig.SupervisoryAuthority;
import se.digg.wallet.pki.config.VerifierRegistrationConfig.LocalizedText;
import se.digg.wallet.pki.config.VerifierRegistrationConfig.RequestedCredential;

class VerifierConfigTest {
  @Test
  void registration_intended_use_ids_must_be_distinct() {
    var registrations = List.of(registration("1", "first.jwt"), registration("1", "second.jwt"));

    assertThatThrownBy(() -> new VerifierConfig(null, signer("signer.p12"),
        supervisoryAuthority(), registrations))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Duplicate verifier intendedUseId: 1");
  }

  @ParameterizedTest
  @ValueSource(strings = {"same.jwt", "nested/../same.jwt"})
  void registration_documents_cannot_overwrite_each_other(String secondJwt) {
    var registrations = List.of(registration("1", "same.jwt"), registration("2", secondJwt));

    assertThatThrownBy(() -> new VerifierConfig(null, signer("signer.p12"),
        supervisoryAuthority(), registrations))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Verifier output paths must be distinct");
  }

  @Test
  void a_registration_cannot_overwrite_the_shared_signer_keystore() {
    var registrations = List.of(registration("1", "signer.p12"));

    assertThatThrownBy(() -> new VerifierConfig(null, signer("signer.p12"),
        supervisoryAuthority(), registrations))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Verifier output paths must be distinct");
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void registration_outputs_cannot_overwrite_the_access_keystore(boolean collideWithKeystore) {
    var access = new VerifierConfig.Access("access.p12", null, "Access", null,
        new PasswordSource("ACCESS_PASSWORD", null));
    var signer = signer(collideWithKeystore ? "access.p12" : "signer.p12");
    var registration = registration("1", collideWithKeystore ? "registration.jwt" : "access.p12");

    assertThatThrownBy(() -> new VerifierConfig(access, signer, supervisoryAuthority(),
        List.of(registration)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Verifier output paths must be distinct");
  }

  @Test
  void registration_documents_require_a_signer() {
    var registrations = List.of(registration("1", "registration.jwt"));

    assertThatThrownBy(() -> new VerifierConfig(null, null, supervisoryAuthority(), registrations))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("verifier.registrationSigner is required");
  }

  @Test
  void registration_documents_require_a_common_supervisory_authority() {
    var registrations = List.of(registration("1", "registration.jwt"));

    assertThatThrownBy(() -> new VerifierConfig(null, signer("signer.p12"), null, registrations))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("verifier.supervisoryAuthority is required");
  }

  @Test
  void changing_the_input_list_does_not_change_the_validated_registrations() {
    var first = registration("1", "first.jwt");
    var second = registration("2", "second.jwt");
    var registrations = new ArrayList<>(List.of(first, second));

    var config =
        new VerifierConfig(null, signer("signer.p12"), supervisoryAuthority(), registrations);
    registrations.clear();

    assertThat(config.registrations()).containsExactly(first, second);
    assertThatThrownBy(() -> config.registrations().clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  private VerifierRegistrationConfig registration(String intendedUseId, String jwt) {
    return new VerifierRegistrationConfig(jwt, "Service", "wallet-ecosystem",
        intendedUseId, "https://example.test", List.of(new LocalizedText("en", "Service")),
        List.of(new LocalizedText("en", "Verification")),
        List.of(new RequestedCredential("urn:example:credential:1", List.of("reference"))), 30);
  }

  private VerifierConfig.RegistrationSigner signer(String keystore) {
    return new VerifierConfig.RegistrationSigner(keystore, null, "Registration Signer", null,
        new PasswordSource("REGISTRATION_PASSWORD", null));
  }

  private SupervisoryAuthority supervisoryAuthority() {
    return new SupervisoryAuthority("Service", "SE", "help@example.test");
  }
}
