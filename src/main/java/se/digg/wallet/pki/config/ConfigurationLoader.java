// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.nodes.NodeId;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;
import org.yaml.snakeyaml.resolver.Resolver;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.json.JsonMapper;

/** Loads a strict schema and resolves all filesystem inputs against the configuration file. */
public class ConfigurationLoader {
  private final JsonMapper mapper = JsonMapper.builder()
      .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
      .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS).build();

  public PkiConfiguration load(Path source) {
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
      PkiConfiguration config = mapper.convertValue(value, PkiConfiguration.class);
      if (config == null) {
        throw new PkiConfigurationException("Configuration is empty");
      }
      Path base = source.toAbsolutePath().normalize().getParent();
      PkiConfiguration resolved = resolve(base, config);
      Path authorities = Path.of(resolved.authorityDirectory());
      Path output = Path.of(resolved.outputDirectory());
      if (authorities.startsWith(output) || output.startsWith(authorities)) {
        throw new PkiConfigurationException(
            "Authority and output directories must be separate and non-nested");
      }
      return resolved;
    } catch (IOException | RuntimeException e) {
      if (e instanceof PkiConfigurationException configurationException) {
        throw configurationException;
      }
      throw new PkiConfigurationException(
          "Invalid configuration in " + source + ": " + e.getMessage(), e);
    }
  }

  private static PkiConfiguration resolve(Path base, PkiConfiguration c) {
    var pid = c.pidIssuer();
    var wallet = c.walletProvider();
    var verifier = c.verifier();
    var trust = c.trustSource();
    return new PkiConfiguration(path(base, c.authorityDirectory()),
        path(base, c.outputDirectory()), c.publicationBaseUrl(), c.organization(),
        pid == null ? null
            : new PidIssuerConfig(authority(base, pid.authority()), pid.signing(),
                pid.encryption(), password(base, pid.keystorePassword()), pid.registration()),
        wallet == null ? null
            : new WalletProviderConfig(authority(base, wallet.authority()),
                wallet.signing(), password(base, wallet.keystorePassword())),
        verifier == null ? null
            : new VerifierConfig(
                verifier.access() == null ? null
                    : new VerifierConfig.Access(
                        authority(base, verifier.access().authority()),
                        verifier.access().commonName(),
                        verifier.access().subjectAlternativeNames(),
                        password(base, verifier.access().keystorePassword())),
                verifier.registration() == null ? null
                    : new VerifierConfig.Registration(
                        authority(base, verifier.registration().authority()),
                        verifier.registration().commonName(),
                        password(base, verifier.registration().keystorePassword()),
                        verifier.registration().registration())),
        trust == null ? null
            : new TrustSourceConfig(authority(base, trust.authority()),
                new TrustSourceConfig.Signer(trust.signer().commonName(),
                    password(base, trust.signer().keystorePassword())),
                lote(base, trust.lote()), trust.statusList()));
  }

  private static LoteConfig lote(Path base, LoteConfig c) {
    var a = c.trustedAuthorities();
    return new LoteConfig(c.name(), c.sequenceNumber(), c.validityDays(),
        new LoteConfig.TrustedAuthorities(
            entity(base, a.pidIssuer()), entity(base, a.walletProvider()),
            entity(base, a.verifierAccess()), entity(base, a.verifierRegistration())));
  }

  private static LoteConfig.Entity entity(Path base, LoteConfig.Entity e) {
    return new LoteConfig.Entity(e.entityName(), e.serviceName(), e.informationUrl(),
        e.streetAddress(), path(base, e.certificateFile()));
  }

  private static AuthorityConfig authority(Path base, AuthorityConfig a) {
    return new AuthorityConfig(a.source(), a.commonName(), path(base, a.certificateFile()),
        path(base, a.privateKeyFile()), path(base, a.crlFile()));
  }

  private static PasswordSource password(Path base, PasswordSource p) {
    return new PasswordSource(p.env(), path(base, p.file()));
  }

  private static String path(Path base, String value) {
    return value == null ? null : base.resolve(value).normalize().toString();
  }
}
