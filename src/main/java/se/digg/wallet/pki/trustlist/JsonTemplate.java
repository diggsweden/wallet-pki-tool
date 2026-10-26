// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.trustlist;

import java.util.Map;
import tools.jackson.databind.ObjectMapper;

/** Renders JSON placeholders using Jackson to serialize each supplied value. */
final class JsonTemplate {
  private JsonTemplate() {}

  static String render(ObjectMapper json, String template, Map<String, ?> values) {
    String result = template;
    for (var entry : values.entrySet()) {
      result = result.replace("${%s}".formatted(entry.getKey()),
          json.writeValueAsString(entry.getValue()));
    }
    return result;
  }
}
