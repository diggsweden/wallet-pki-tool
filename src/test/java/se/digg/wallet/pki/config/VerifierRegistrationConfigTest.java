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
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import se.digg.wallet.pki.config.VerifierRegistrationConfig.LocalizedText;
import se.digg.wallet.pki.config.VerifierRegistrationConfig.RequestedCredential;

class VerifierRegistrationConfigTest {
  @ParameterizedTest
  @NullAndEmptySource
  void registration_requires_at_least_one_credential(List<RequestedCredential> credentials) {
    assertThatThrownBy(() -> registration(credentials))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("registration.requestedCredentials");
  }

  @ParameterizedTest
  @ValueSource(strings = {"urn:eudi:pid:1", "urn:example:credential:1"})
  void vct_cannot_be_requested_twice_even_with_different_claims(String vct) {
    var credentials = List.of(new RequestedCredential(vct, List.of("family_name")),
        new RequestedCredential(vct, List.of("given_name")));

    assertThatThrownBy(() -> registration(credentials))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Duplicate requested credential VCT")
        .hasMessageContaining(vct);
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "relative-type", "/relative/type", "urn:invalid uri"})
  void credential_types_must_be_absolute_uris(String vct) {
    assertThatThrownBy(() -> new RequestedCredential(vct, List.of("family_name")))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @NullAndEmptySource
  void each_credential_requires_claims(List<String> claims) {
    assertThatThrownBy(() -> new RequestedCredential("urn:eudi:pid:1", claims))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("registration.requestedCredentials.claims");
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", ".family_name", "address.", "address..locality", "given name"})
  void claim_paths_require_nonempty_segments_without_whitespace(String path) {
    var claims = new ArrayList<String>();
    claims.add(path);

    assertThatThrownBy(() -> new RequestedCredential("urn:eudi:pid:1", claims))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @ValueSource(strings = {"family_name", "address.street_address", "customTitle",
      "course.code2", "qualification-level"})
  void claim_paths_are_not_restricted_to_pid_field_names(String path) {
    var credential = new RequestedCredential("urn:example:credential:1",
        List.of(path));

    assertThat(credential.claims()).containsExactly(path);
  }

  @Test
  void later_changes_to_input_lists_do_not_change_the_registration() {
    var claims = new ArrayList<>(List.of("family_name"));
    var credentials = new ArrayList<>(List.of(new RequestedCredential("urn:eudi:pid:1", claims)));

    var config = registration(credentials);
    claims.add("given_name");
    credentials.clear();

    assertThat(config.requestedCredentials())
        .containsExactly(new RequestedCredential("urn:eudi:pid:1", List.of("family_name")));
  }

  @Test
  void credential_requests_cannot_be_changed_after_validation() {
    var config = registration(List.of(new RequestedCredential("urn:eudi:pid:1",
        List.of("family_name"))));

    assertThatThrownBy(() -> config.requestedCredentials().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> config.requestedCredentials().getFirst().claims().clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  private VerifierRegistrationConfig registration(List<RequestedCredential> credentials) {
    return new VerifierRegistrationConfig("registration.jwt", "Service", "wallet-ecosystem", "1",
        "https://example.test", List.of(new LocalizedText("en", "Service")),
        List.of(new LocalizedText("en", "Identification")), credentials, 30);
  }
}
