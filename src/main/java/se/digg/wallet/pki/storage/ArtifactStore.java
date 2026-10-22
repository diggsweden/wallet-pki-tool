// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: CC0-1.0

package se.digg.wallet.pki.storage;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import se.digg.wallet.pki.config.EnvironmentConfiguration;
import se.digg.wallet.pki.config.PkiConfigurationException;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/** Owns artifact locations and commits state and exports with one publication pointer. */
public final class ArtifactStore {
  public static final JsonMapper JSON = JsonMapper.builder()
      .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
      .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS).build();

  private final Path state;
  private final Path output;
  private final String environment;

  public ArtifactStore(EnvironmentConfiguration configuration) {
    state = Path.of(configuration.stateDir());
    output = Path.of(configuration.outputDir());
    environment = configuration.environment();
    rejectSymlinks(state);
    rejectSymlinks(output);
  }

  public record Resource(String specificationDigest, String expiresAt, String certificateDigest,
      String primaryAlias) {
  }

  public record Manifest(int schemaVersion, String toolVersion, String environment,
      String generation, String configurationDigest, String createdAt,
      Map<String, Resource> resources, Map<String, String> files, Map<String, String> stateFiles) {
    public Manifest {
      resources = Map.copyOf(resources);
      files = Map.copyOf(files);
      stateFiles = Map.copyOf(stateFiles);
    }
  }

  public record Snapshot(Path state, Path bundle, Manifest manifest) {
    public String generation() {
      return manifest.generation();
    }
  }

  /** Inspects the committed generation without creating directories or resolving secrets. */
  public Snapshot current() {
    Path current = output.resolve("current");
    if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
      return null;
    }
    try {
      if (!Files.isSymbolicLink(current)) {
        throw new PkiConfigurationException("Bundle current pointer must be a symbolic link");
      }
      Path target = Files.readSymbolicLink(current);
      if (target.isAbsolute() || target.getNameCount() != 2
          || !target.getName(0).toString().equals("generations")
          || !target.getFileName().toString().matches("[0-9a-f-]{36}")) {
        throw new PkiConfigurationException("Invalid bundle current pointer");
      }
      Path bundle = output.resolve(target);
      Path privateState = state.resolve(target);
      rejectSymlinks(bundle);
      rejectSymlinks(privateState);
      byte[] manifestBytes = Files.readAllBytes(privateState.resolve("manifest.json"));
      if (!MessageDigest.isEqual(manifestBytes,
          Files.readAllBytes(bundle.resolve("manifest.json")))) {
        throw new PkiConfigurationException("State and bundle manifests disagree");
      }
      Manifest manifest = JSON.readValue(manifestBytes, Manifest.class);
      if (manifest.schemaVersion() != 1 || !manifest.environment().equals(environment)
          || !manifest.generation().equals(target.getFileName().toString())) {
        throw new PkiConfigurationException("Committed state belongs to another environment");
      }
      return new Snapshot(privateState, bundle, manifest);
    } catch (IOException e) {
      throw new PkiConfigurationException("Cannot read committed artifact state", e);
    }
  }

  public Lock lock() throws IOException {
    directory(state, true);
    FileChannel channel = FileChannel.open(state.resolve("operation.lock"),
        StandardOpenOption.CREATE, StandardOpenOption.WRITE);
    try {
      FileLock fileLock = channel.tryLock();
      if (fileLock != null) {
        return new Lock(channel, fileLock);
      }
      throw new PkiConfigurationException("Another operation is using this state directory");
    } catch (IOException | RuntimeException e) {
      channel.close();
      throw e;
    }
  }

  public record Lock(FileChannel channel, FileLock lock) implements AutoCloseable {
    @Override
    public void close() throws IOException {
      try {
        lock.release();
      } finally {
        channel.close();
      }
    }
  }

  public Staging begin(Snapshot previous) throws IOException {
    return new Staging(previous);
  }

  public final class Staging implements AutoCloseable {
    private final String generation = UUID.randomUUID().toString();
    private final Path privateState = state.resolve("generations/.staging-" + generation);
    private final Path bundle = output.resolve("generations/.staging-" + generation);
    private final Path finalState = state.resolve("generations/" + generation);
    private final Path finalBundle = output.resolve("generations/" + generation);
    private boolean committed;

    private Staging(Snapshot previous) throws IOException {
      try {
        directory(privateState, true);
        directory(bundle, true);
        if (previous != null) {
          try (var paths = Files.walk(previous.state())) {
            for (Path path : paths.toList()) {
              rejectSymlinks(path);
              Path destination = privateState.resolve(previous.state().relativize(path));
              if (Files.isDirectory(path)) {
                directory(destination, true);
              } else {
                Files.copy(path, destination);
              }
            }
          }
        }
      } catch (IOException | RuntimeException e) {
        close();
        throw e;
      }
    }

    public Path state() {
      return privateState;
    }

    public Path bundle() {
      return bundle;
    }

    public String generation() {
      return generation;
    }

    public Path commit(Manifest manifest) throws IOException {
      byte[] bytes = JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(manifest);
      write(privateState.resolve("manifest.json"), bytes, true);
      write(bundle.resolve("manifest.json"), bytes, false);
      directory(bundle, false);
      Files.move(privateState, finalState, StandardCopyOption.ATOMIC_MOVE);
      Files.move(bundle, finalBundle, StandardCopyOption.ATOMIC_MOVE);
      Path pointer = output.resolve(".current-" + generation);
      try {
        Files.createSymbolicLink(pointer, Path.of("generations", generation));
        Files.move(pointer, output.resolve("current"), StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING);
        committed = true;
        return finalBundle;
      } finally {
        Files.deleteIfExists(pointer);
      }
    }

    @Override
    public void close() throws IOException {
      if (!committed) {
        deleteTree(privateState);
        deleteTree(bundle);
        deleteTree(finalState);
        deleteTree(finalBundle);
      }
    }
  }

  public static Path resource(Path root, String reference, String extension) {
    String[] parts = reference.split(":", -1);
    if (parts.length != 2 || !parts[1].matches("[a-z][a-z0-9-]*")
        || !java.util.Set.of("authority", "identity", "document", "truststore")
            .contains(parts[0])) {
      throw new PkiConfigurationException("Invalid resource reference: " + reference);
    }
    return root.resolve(parts[0] + "/" + parts[1] + extension);
  }

  public static void write(Path path, byte[] contents, boolean secret) throws IOException {
    directory(path.getParent(), secret);
    if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
      rejectSymlinks(path);
    } else if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      Files.createFile(path, PosixFilePermissions.asFileAttribute(
          PosixFilePermissions.fromString(secret ? "rw-------" : "rw-r--r--")));
    }
    Files.write(path, contents);
  }

  public static void directory(Path path, boolean secret) throws IOException {
    rejectSymlinks(path);
    Files.createDirectories(path);
    if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      Files.setPosixFilePermissions(path,
          PosixFilePermissions.fromString(secret ? "rwx------" : "rwxr-xr-x"));
    }
  }

  public static String digest(Object value) {
    return digest(JSON.writeValueAsBytes(value));
  }

  public static String digest(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is unavailable", e);
    }
  }

  public static void rejectSymlinks(Path path) {
    for (Path ancestor = path.toAbsolutePath(); ancestor != null; ancestor = ancestor.getParent()) {
      if (Files.isSymbolicLink(ancestor)) {
        throw new PkiConfigurationException("Artifact path contains a symbolic link: " + ancestor);
      }
    }
  }

  private static void deleteTree(Path root) throws IOException {
    if (Files.exists(root)) {
      try (var paths = Files.walk(root)) {
        for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
          Files.delete(path);
        }
      }
    }
  }
}
