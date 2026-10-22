// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import se.digg.wallet.pki.config.VerifierRegistrationConfig.LocalizedText;
import se.digg.wallet.pki.config.VerifierRegistrationConfig.SupervisoryAuthority;
import se.digg.wallet.pki.trustlist.RegistrationDocuments.Credential;
import se.digg.wallet.pki.trustlist.RegistrationDocuments.CredentialMetadata;
import se.digg.wallet.pki.trustlist.RegistrationDocuments.PidDocument;
import se.digg.wallet.pki.trustlist.RegistrationDocuments.PidPayload;
import se.digg.wallet.pki.trustlist.RegistrationDocuments.RequestedClaim;
import se.digg.wallet.pki.trustlist.RegistrationDocuments.Status;
import se.digg.wallet.pki.trustlist.RegistrationDocuments.StatusList;
import se.digg.wallet.pki.trustlist.RegistrationDocuments.VerifierPayload;
import tools.jackson.databind.json.JsonMapper;

class RegistrationDocumentsTest {
  @Test
  void caller_mutations_cannot_change_registration_payload_json() {
    var path = new ArrayList<>(List.of("address", "street_address"));
    var vctValues = new ArrayList<>(List.of("urn:eudi:pid:1"));
    var requestedClaim = new RequestedClaim(path);
    var metadata = new CredentialMetadata(vctValues);
    var claims = new ArrayList<>(List.of(requestedClaim));
    var credential = new Credential("dc+sd-jwt", metadata, claims);
    var credentials = new ArrayList<>(List.of(credential));
    var description = new ArrayList<>(List.of(new LocalizedText("en", "Identity service")));
    var purpose = new ArrayList<>(List.of(new LocalizedText("en", "Identification")));
    var entitlements =
        new ArrayList<>(List.of("https://uri.etsi.org/19475/Entitlement/Service_Provider"));
    var policies = new ArrayList<>(List.of("0.4.0.19475.3.1"));
    var payload = new VerifierPayload("Service", "VATSE-12345678", "SE", 1, 2,
        "https://example.test/registry", description, entitlements, purpose, credentials,
        "wallet-ecosystem", "1", "https://example.test/privacy", "https://example.test/info",
        "https://example.test/support",
        new SupervisoryAuthority("Authority", "SE", "help@example.test"),
        policies, "https://example.test/policy",
        new Status(new StatusList("https://example.test/status", 0)));
    var json = JsonMapper.builder().build();
    String original = json.writeValueAsString(payload);

    path.clear();
    vctValues.clear();
    claims.clear();
    credentials.clear();
    description.clear();
    purpose.clear();
    entitlements.clear();
    policies.clear();

    assertThat(json.writeValueAsString(payload)).isEqualTo(original);
    assertThatThrownBy(() -> requestedClaim.path().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> metadata.vctValues().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> credential.claim().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    for (List<?> values : List.of(payload.description(), payload.purpose(), payload.entitlements(),
        payload.credentials(), payload.policyId())) {
      assertThatThrownBy(values::clear).isInstanceOf(UnsupportedOperationException.class);
    }
  }

  @Test
  void pid_document_header_entries_are_snapshots() {
    Map<String, Object> headers = new HashMap<>();
    headers.put("alg", "ES256");
    var document =
        new PidDocument(headers, new PidPayload("did:web:example.test", "did:web:example.test"));

    headers.put("alg", "changed");

    assertThat(document.headers()).containsEntry("alg", "ES256");
    assertThatThrownBy(() -> document.headers().put("alg", "changed"))
        .isInstanceOf(UnsupportedOperationException.class);
  }
}
