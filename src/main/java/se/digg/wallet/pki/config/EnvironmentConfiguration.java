// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import se.digg.wallet.pki.crypto.CertificateProfileType;

/** Versioned description of an environment and the artifacts its consumers require. */
public record EnvironmentConfiguration(
    int schemaVersion, String environment, String stateDir, String outputDir,
    List<Authority> authorities, List<Identity> identities, List<Document> documents,
    List<TrustStore> trustStores, List<Export> exports) {

  public EnvironmentConfiguration {
    require(schemaVersion == 1, "schemaVersion must be 1; legacy configurations must be migrated");
    identifier(environment);
    text(stateDir, "stateDir");
    text(outputDir, "outputDir");
    authorities = copy(authorities);
    identities = copy(identities);
    documents = copy(documents);
    trustStores = copy(trustStores);
    exports = copy(exports);
  }

  public record Authority(String id, String commonName, boolean create, String keyFile,
      String certFile, String certificateUrl, String crlUrl) {
    public Authority {
      identifier(id);
      text(commonName, "authority commonName");
      require((keyFile == null) == (certFile == null), "keyFile and certFile must be paired");
      require(!create || keyFile == null, "create cannot be combined with imported CA files");
      url(certificateUrl, "certificateUrl");
      url(crlUrl, "crlUrl");
    }
  }

  public record Identity(String id, String profile, String authority, String commonName,
      String organizationIdentifier, String country, List<String> sans, String alias,
      String passwordEnv, String passwordFile, int validityDays, int renewBeforeDays,
      String cpsUrl) {
    public Identity {
      identifier(id);
      identifier(authority);
      text(profile, "identity profile");
      profile = CertificateProfileType.fromString(profile).value();
      text(commonName, "identity commonName");
      country = country == null ? "SE" : country;
      require(country.matches("[A-Z]{2}"), "country must contain two uppercase letters");
      sans = copy(sans);
      for (String san : sans) {
        text(san, "subject alternative name");
        if (san.regionMatches(true, 0, "IP:", 0, 3)) {
          java.net.InetAddress.ofLiteral(san.substring(3).trim());
        } else if (san.regionMatches(true, 0, "DNS:", 0, 4)) {
          text(san.substring(4).trim(), "DNS subject alternative name");
        } else if (san.regionMatches(true, 0, "URI:", 0, 4)) {
          require(java.net.URI.create(san.substring(4).trim()).isAbsolute(),
              "URI subject alternative name must be absolute");
        }
      }
      alias = alias == null ? id.replace('-', '_') : alias;
      require(alias.matches("[a-z0-9_-]+"), "keystore alias must use lowercase letters");
      require(!Set.of("nonce-encryption", "request-encryption").contains(alias),
          "primary alias collides with an encryption key alias");
      secret(passwordEnv, passwordFile);
      validityDays = validityDays == 0 ? 825 : validityDays;
      lifetime(validityDays, renewBeforeDays);
      if (profile.startsWith("relying-party-")) {
        text(organizationIdentifier, "relying party organizationIdentifier");
      }
      url(cpsUrl, "cpsUrl");
    }

    public CertificateConfig certificateConfig() {
      return new CertificateConfig(id, profile, authority, id + ".p12", passwordEnv,
          passwordFile, sans, commonName, country, organizationIdentifier, alias);
    }
  }

  public record Entity(String reference, String role, String name, String uri, String country) {
    public Entity {
      text(reference, "entity reference");
      require(Set.of("pid", "wallet", "wrpac", "wrprc").contains(role),
          "entity role must be pid, wallet, wrpac or wrprc");
      text(name, "entity name");
      url(uri, "entity uri");
      text(uri, "entity uri");
      country = country == null ? "SE" : country;
    }
  }

  public record Document(String id, String type, String signer, List<Entity> entities,
      Map<String, Object> claims, String url, String statusBits, int validityDays,
      int renewBeforeDays, String schemeName, String schemeOperator, String territory) {
    public Document {
      identifier(id);
      identifier(signer);
      require(Set.of("lote", "status-list", "registration").contains(type),
          "document type must be lote, status-list or registration");
      entities = copy(entities);
      claims = claims == null ? Map.of() : Map.copyOf(claims);
      validityDays = validityDays == 0 ? 365 : validityDays;
      lifetime(validityDays, renewBeforeDays);
      if ("lote".equals(type)) {
        require(!entities.isEmpty(), "LoTE entities must be explicit");
        text(schemeName, "LoTE schemeName");
        text(schemeOperator, "LoTE schemeOperator");
        text(territory, "LoTE territory");
      } else if ("status-list".equals(type)) {
        text(url, "status-list url");
        EnvironmentConfiguration.url(url, "status-list url");
      } else {
        require(!claims.isEmpty(), "registration claims must be supplied");
      }
    }
  }

  public record TrustedCertificate(String reference, String alias) {
    public TrustedCertificate {
      text(reference, "trusted certificate reference");
      require(alias != null && alias.matches("[a-z0-9_-]+"),
          "truststore alias must use lowercase letters");
    }
  }

  public record TrustStore(String id, List<TrustedCertificate> certificates, String passwordEnv,
      String passwordFile) {
    public TrustStore {
      identifier(id);
      certificates = copy(certificates);
      require(!certificates.isEmpty(), "truststore certificates must be explicit");
      require(
          certificates.stream().map(TrustedCertificate::alias).distinct().count() == certificates
              .size(),
          "duplicate truststore alias");
      secret(passwordEnv, passwordFile);
    }
  }

  public record Export(String source, String format, String path, String variable) {
    public Export {
      text(source, "export source");
      require(Set.of("pkcs12", "certificate", "crl", "compact", "env", "json", "file")
          .contains(format), "unsupported export format");
      text(path, "export path");
      Path relative = Path.of(path).normalize();
      require(!relative.isAbsolute() && !relative.startsWith("..")
          && relative.getNameCount() > 1, "export path must be relative to its bundle");
      String partition = "pkcs12".equals(format) ? "private" : "public";
      require(relative.startsWith(partition), "export must be under " + partition + "/");
      if ("env".equals(format)) {
        require(variable != null && variable.matches("[A-Z_][A-Z0-9_]*"),
            "env export requires an uppercase variable name");
      }
      path = relative.toString();
    }
  }

  private static void lifetime(int days, int renewBefore) {
    require(days > 0 && renewBefore >= 0 && renewBefore < days,
        "validityDays must be positive and exceed renewBeforeDays");
  }

  private static void secret(String env, String file) {
    require((env != null && !env.isBlank()) != (file != null && !file.isBlank()),
        "specify exactly one of passwordEnv and passwordFile");
  }

  private static void identifier(String value) {
    require(value != null && value.matches("[a-z][a-z0-9-]*"),
        "identifiers must match [a-z][a-z0-9-]*");
  }

  private static void url(String value, String field) {
    if (value != null) {
      java.net.URI uri = java.net.URI.create(value);
      require(Set.of("http", "https").contains(uri.getScheme()) && uri.getHost() != null,
          field + " must be an absolute HTTP(S) URL");
    }
  }

  private static void text(String value, String field) {
    require(value != null && !value.isBlank(), field + " is required");
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new IllegalArgumentException(message);
    }
  }

  private static <T> List<T> copy(List<T> values) {
    return values == null ? List.of() : List.copyOf(values);
  }
}
