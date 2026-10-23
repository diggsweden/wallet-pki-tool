// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.cli;

import java.io.PrintWriter;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;
import java.util.function.BiConsumer;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ScopeType;
import se.digg.wallet.pki.application.RoleProvisioner;
import se.digg.wallet.pki.application.WalletServicesPkiGenerator;
import se.digg.wallet.pki.config.ConfigurationLoader;
import se.digg.wallet.pki.config.PkiConfiguration;
import se.digg.wallet.pki.config.SecretResolver;
import se.digg.wallet.pki.domain.AuthorityRole;

/** Composition root: CLI paths select named wallet operations. */
@Command(name = "wallet-pki", mixinStandardHelpOptions = true, version = "wallet-pki 0.1.0",
    description = "Generate certificates and signed documents for explicit wallet roles.",
    subcommands = CommandLine.HelpCommand.class)
public class WalletPkiCli {
  @Option(names = {"-c", "--config"}, required = true, scope = ScopeType.INHERIT,
      description = "Wallet YAML configuration; only the selected operation's roles are required.")
  private Path configuration;
  private final CommandLine commandLine;

  public WalletPkiCli() {
    this(new ConfigurationLoader(), new SecretResolver(), null, null);
  }

  public WalletPkiCli(PrintWriter out, PrintWriter err) {
    this(new ConfigurationLoader(), new SecretResolver(), out, err);
  }

  public WalletPkiCli(ConfigurationLoader loader, SecretResolver secrets, PrintWriter out,
      PrintWriter err) {
    var roles = new RoleProvisioner(secrets);
    commandLine = new CommandLine(this);
    commandLine.addSubcommand("authorities",
        group("authorities", "Manage local wallet authorities.")
            .addSubcommand(new InitAuthoritiesCommand(loader, () -> configuration)));
    commandLine.addSubcommand("pid-issuer", participant("pid-issuer", loader,
        "Create three new keys, replace the PID keystore and rebuild issuer registration JWT/JSON. "
            + "Requires the PID authority and password.",
        roles::generatePidIssuer));
    commandLine.addSubcommand("wallet-provider", participant("wallet-provider", loader,
        "Create a new attestation key and replace the wallet-provider keystore. "
            + "Requires the wallet-provider authority and password.",
        roles::generateWalletProvider));
    commandLine.addSubcommand("verifier", group("verifier", "Generate verifier identities.")
        .addSubcommand("access", participant("access", loader,
            "Create a new access key and replace the verifier access keystore. "
                + "Requires the access authority and password.",
            roles::generateVerifierAccess))
        .addSubcommand("registration", participant("registration", loader,
            "Create a new registration key and replace the keystore, JWT and environment export. "
                + "Requires the registration authority and password.",
            roles::generateVerifierRegistration)));
    var trust = participant("trust-source", loader,
        "Create a new trust signer, replace its keystore/certificate and rebuild LoTE/status list. "
            + "Requires the trust-source authority/password and four public participant CAs.",
        roles::generateTrustSource);
    trust.addSubcommand("lote", participant("lote", loader,
        "Replace only LoTE using the existing signer. Requires its password and five public CAs; "
            + "no CA private keys or participant passwords are read.",
        roles::generateLote));
    trust.addSubcommand("status-list", participant("status-list", loader,
        "Replace only the all-valid test status list using the existing signer. Requires its "
            + "password and public trust-source CA; no participant authorities are read.",
        roles::generateStatusList));
    commandLine.addSubcommand("trust-source", trust);
    commandLine.addSubcommand("ecosystem", participant("ecosystem", loader,
        "Generate all five roles with new keys and rebuild their documents. "
            + "Requires complete role configuration, five initialized authorities and passwords; "
            + "preflight prerequisites before replacing outputs.",
        new WalletServicesPkiGenerator(secrets)::generate));
    commandLine.registerConverter(AuthorityRole.class,
        value -> Arrays.stream(AuthorityRole.values())
            .filter(role -> role.name().toLowerCase(Locale.ROOT).replace('_', '-').equals(value))
            .findFirst().orElseThrow(() -> new CommandLine.TypeConversionException(
                "Unknown authority role: " + value)));
    if (out != null)
      commandLine.setOut(out);
    if (err != null)
      commandLine.setErr(err);
  }

  private CommandLine participant(String name, ConfigurationLoader loader, String description,
      BiConsumer<PkiConfiguration, PrintWriter> operation) {
    var generate = new CommandLine(new GenerateCommand(loader, () -> configuration, operation));
    generate.getCommandSpec().usageMessage().description(description);
    return group(name, description).addSubcommand(generate);
  }

  private CommandLine group(String name, String description) {
    var spec = CommandSpec.create().name(name).mixinStandardHelpOptions(true);
    spec.usageMessage().description(description);
    return new CommandLine(spec);
  }

  public static void main(String[] args) {
    System.exit(new WalletPkiCli().execute(args));
  }

  public int execute(String... args) {
    return commandLine.execute(args);
  }
}
