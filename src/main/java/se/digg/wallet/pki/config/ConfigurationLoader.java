// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.nodes.NodeId;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;
import org.yaml.snakeyaml.resolver.Resolver;
import se.digg.wallet.pki.config.EnvironmentConfiguration.Authority;
import se.digg.wallet.pki.config.EnvironmentConfiguration.Export;
import se.digg.wallet.pki.config.EnvironmentConfiguration.Identity;
import se.digg.wallet.pki.config.EnvironmentConfiguration.TrustStore;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.json.JsonMapper;

/** Loads a strict schema and resolves all filesystem inputs against the configuration file. */
public class ConfigurationLoader {
  private final JsonMapper mapper = JsonMapper.builder()
      .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
      .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS).build();

  public EnvironmentConfiguration load(Path source) {
    if (source == null || !Files.isRegularFile(source)) {
      throw new PkiConfigurationException("Configuration file not found: " + source);
    }
    LoaderOptions options = new LoaderOptions();
    options.setAllowDuplicateKeys(false);
    options.setMaxAliasesForCollections(0);
    options.setCodePointLimit(1_000_000);
    try (var input = Files.newInputStream(source)) {
      DumperOptions dumper = new DumperOptions();
      Resolver resolver = new Resolver() {
        @Override
        public Tag resolve(NodeId kind, String value, boolean implicit) {
          Tag tag = super.resolve(kind, value, implicit);
          return Tag.BOOL.equals(tag) && !"true".equalsIgnoreCase(value)
              && !"false".equalsIgnoreCase(value) ? Tag.STR : tag;
        }
      };
      Object value = new Yaml(new SafeConstructor(options), new Representer(dumper),
          dumper, options, resolver).load(input);
      EnvironmentConfiguration config = mapper.convertValue(value, EnvironmentConfiguration.class);
      if (config == null) {
        throw new PkiConfigurationException("Configuration is empty");
      }
      Path base = source.toAbsolutePath().normalize().getParent();
      EnvironmentConfiguration resolved = new EnvironmentConfiguration(config.schemaVersion(),
          config.environment(), resolve(base, config.stateDir()), resolve(base, config.outputDir()),
          config.authorities().stream().map(a -> new Authority(a.id(), a.commonName(), a.create(),
              resolve(base, a.keyFile()), resolve(base, a.certFile()), a.certificateUrl(),
              a.crlUrl()))
              .toList(),
          config.identities().stream().map(i -> new Identity(i.id(), i.profile(), i.authority(),
              i.commonName(), i.organizationIdentifier(), i.country(), i.sans(), i.alias(),
              i.passwordEnv(), resolve(base, i.passwordFile()), i.validityDays(),
              i.renewBeforeDays(), i.cpsUrl())).toList(),
          config.documents(), config.trustStores().stream().map(t -> new TrustStore(t.id(),
              t.certificates(), t.passwordEnv(), resolve(base, t.passwordFile()))).toList(),
          config.exports().stream().map(e -> new Export(
              "file".equals(e.format()) && e.source().startsWith("file:")
                  ? "file:" + resolve(base, e.source().substring(5))
                  : e.source(),
              e.format(), e.path(), e.variable())).toList());
      validate(resolved);
      return resolved;
    } catch (IOException | RuntimeException e) {
      if (e instanceof PkiConfigurationException configurationException) {
        throw configurationException;
      }
      throw new PkiConfigurationException("Invalid configuration in " + source + ": "
          + e.getMessage(), e);
    }
  }

  private static void validate(EnvironmentConfiguration config) {
    Path state = Path.of(config.stateDir());
    Path output = Path.of(config.outputDir());
    require(!state.startsWith(output) && !output.startsWith(state),
        "stateDir and outputDir must be separate, non-nested directories");
    Map<String, String> kinds = new LinkedHashMap<>();
    config.authorities().forEach(a -> add(kinds, "authority:" + a.id(), "authority"));
    config.identities().forEach(i -> add(kinds, "identity:" + i.id(), "identity"));
    config.documents().forEach(d -> add(kinds, "document:" + d.id(), "document"));
    config.trustStores().forEach(t -> add(kinds, "truststore:" + t.id(), "truststore"));
    config.identities().forEach(i -> reference(kinds, "authority:" + i.authority(),
        Set.of("authority")));
    config.documents().forEach(d -> {
      reference(kinds, "identity:" + d.signer(), Set.of("identity"));
      Identity signer = config.identities().stream().filter(i -> i.id().equals(d.signer()))
          .findFirst().orElseThrow();
      require(!"encryption".equals(signer.profile()),
          "Document signer must support digital signatures: " + d.signer());
      d.entities().forEach(e -> reference(kinds, e.reference(), Set.of("authority", "identity")));
    });
    config.trustStores().forEach(t -> t.certificates()
        .forEach(r -> reference(kinds, r.reference(), Set.of("authority", "identity"))));
    Set<Path> paths = new HashSet<>();
    config.exports().forEach(e -> {
      Set<String> allowed = switch (e.format()) {
        case "pkcs12" -> Set.of("identity", "truststore");
        case "certificate" -> Set.of("authority", "identity");
        case "crl" -> Set.of("authority");
        default -> Set.of("document");
      };
      if ("file".equals(e.format())) {
        require(
            e.source().startsWith("file:") && Files.isRegularFile(Path.of(e.source().substring(5))),
            "file export requires an existing file: source");
      } else {
        reference(kinds, e.source(), allowed);
      }
      for (Path p : java.util.List.of(Path.of(e.path()), Path.of(e.path() + ".license"))) {
        require(paths.stream().noneMatch(other -> other.startsWith(p) || p.startsWith(other)),
            "Conflicting export path: " + p);
        paths.add(p);
      }
    });
    require(!config.exports().isEmpty(), "At least one export is required");
  }

  private static void add(Map<String, String> kinds, String reference, String kind) {
    require(kinds.putIfAbsent(reference, kind) == null, "Duplicate reference: " + reference);
  }

  private static void reference(Map<String, String> kinds, String reference, Set<String> allowed) {
    require(kinds.containsKey(reference), "Unknown reference: " + reference);
    require(allowed.contains(kinds.get(reference)), "Invalid reference kind: " + reference);
  }

  private static String resolve(Path base, String path) {
    return path == null ? null : base.resolve(path).normalize().toString();
  }

  private static void require(boolean condition, String message) {
    if (!condition) {
      throw new PkiConfigurationException(message);
    }
  }
}
