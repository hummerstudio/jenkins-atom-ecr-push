package com.jenkinschina.atom.ecrpush;

import com.jenkinschina.atom.sdk.Json;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * The image that is about to be pushed: one manifest and the blobs it names, as files on disk.
 *
 * <p>Two shapes are accepted, because both are what people actually have on a build agent:
 *
 * <ul>
 *   <li>an <b>OCI layout</b> -- a directory (or the tar {@code docker save} writes since 20.10) with {@code index.json}
 *       and content-addressed {@code blobs/sha256/*}. Nothing has to be rewritten: the manifest blob is the manifest,
 *       and the digests are already the file names.
 *   <li>a <b>legacy {@code docker save}</b> tar -- {@code manifest.json} listing a config file and {@code layer.tar}
 *       files. Those layers are plain tars, so the atom writes the schema-2 manifest itself, with the digests it
 *       computes from the files.
 * </ul>
 *
 * <p>A saved image is usually a manifest <em>list</em> (one entry per platform). The registry only takes a single
 * manifest per tag, so the list is resolved to one platform first; with more than one entry and no platform asked for,
 * the atom stops and says which ones are there instead of pushing the wrong architecture.
 */
final class ImageSource {

    private final byte[] manifest;
    private final String mediaType;
    private final Map<String, Path> blobs;
    private final String configDigest;
    private final List<String> layerDigests;
    private final Path extracted;

    private ImageSource(byte[] manifest, String mediaType, Map<String, Path> blobs, String configDigest,
                        List<String> layerDigests, Path extracted) {
        this.manifest = manifest;
        this.mediaType = mediaType;
        this.blobs = blobs;
        this.configDigest = configDigest;
        this.layerDigests = layerDigests;
        this.extracted = extracted;
    }

    static ImageSource load(Path source, String platform, Consumer<String> log) throws IOException {
        if (!Files.exists(source)) {
            throw new IllegalArgumentException("image not found: " + source);
        }
        Path root;
        Path extracted = null;
        if (Files.isDirectory(source)) {
            root = source;
        } else {
            extracted = createOwnerOnlyTempDirectory("ecr-image-");
            int entries = TarReader.extract(source, extracted);
            log.accept("unpacked " + entries + " entries from " + source.getFileName());
            root = extracted;
        }
        Path layout = findLayout(root);
        if (layout == null) {
            throw new IllegalArgumentException("no image in " + source
                    + ": expected an OCI layout (index.json) or a docker save tarball (manifest.json)");
        }
        return Files.exists(layout.resolve("index.json"))
                ? fromOciLayout(layout, platform, extracted, log)
                : fromLegacySave(layout, extracted, log);
    }

    /**
     * A scratch directory only this user can enter: 0700 from creation, so the unpacked image is never readable by
     * another account on the agent. Where POSIX modes do not exist the attribute is left off instead of failing.
     */
    private static Path createOwnerOnlyTempDirectory(String prefix) throws IOException {
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            return Files.createTempDirectory(prefix,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        }
        return Files.createTempDirectory(prefix, new FileAttribute<?>[0]);
    }

    /** The layout root, which may be one directory down inside a tarball. */
    private static Path findLayout(Path root) throws IOException {
        if (Files.isRegularFile(root.resolve("index.json")) || Files.isRegularFile(root.resolve("manifest.json"))) {
            return root;
        }
        try (var children = Files.list(root)) {
            for (Path child : (Iterable<Path>) children::iterator) {
                if (Files.isDirectory(child) && (Files.isRegularFile(child.resolve("index.json"))
                        || Files.isRegularFile(child.resolve("manifest.json")))) {
                    return child;
                }
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ OCI layout

    @SuppressWarnings("unchecked")
    private static ImageSource fromOciLayout(Path root, String platform, Path extracted, Consumer<String> log)
            throws IOException {
        Map<String, Object> index = Json.parseObject(read(root.resolve("index.json")));
        Map<String, Object> descriptor = pick(descriptorList(index.get("manifests")), platform, "index.json");
        byte[] blob = null;
        String type = null;
        // a saved image points at a manifest list; keep following until a manifest names a config
        for (int depth = 0; depth < 3; depth++) {
            blob = Files.readAllBytes(blobPath(root, String.valueOf(descriptor.get("digest"))));
            Map<String, Object> doc = Json.parseObject(new String(blob, StandardCharsets.UTF_8));
            String declared = descriptor.get("mediaType") == null ? null : String.valueOf(descriptor.get("mediaType"));
            type = declared != null ? declared : (doc.get("mediaType") == null ? null : String.valueOf(doc.get("mediaType")));
            if (doc.get("config") instanceof Map && doc.get("layers") instanceof List) {
                break;
            }
            if (!(doc.get("manifests") instanceof List)) {
                throw new IllegalArgumentException("the image index names " + descriptor.get("digest")
                        + ", which is neither a manifest nor a manifest list");
            }
            descriptor = pick(descriptorList(doc.get("manifests")), platform, "the manifest list");
            blob = null;
            type = null;
        }
        if (blob == null) {
            throw new IllegalArgumentException("the manifest list is nested too deeply to resolve");
        }
        Map<String, Object> doc = Json.parseObject(new String(blob, StandardCharsets.UTF_8));
        Map<String, Path> blobs = new LinkedHashMap<>();
        String configDigest = digestOf(doc.get("config"));
        blobs.put(configDigest, blobPath(root, configDigest));
        List<String> layers = new ArrayList<>();
        for (Object layer : descriptorList(doc.get("layers"))) {
            String digest = digestOf(layer);
            layers.add(digest);
            blobs.put(digest, blobPath(root, digest));
        }
        for (Map.Entry<String, Path> entry : blobs.entrySet()) {
            if (!Files.isRegularFile(entry.getValue())) {
                throw new IllegalArgumentException("the image is missing a blob: " + entry.getKey()
                        + " (expected at blobs/sha256/" + hex(entry.getKey()) + ")");
            }
        }
        log.accept("image: " + blobs.size() + " blobs, manifest " + type);
        return new ImageSource(blob, type == null ? MEDIA_MANIFEST : type, blobs, configDigest, layers, extracted);
    }

    private static Path blobPath(Path root, String digest) {
        return root.resolve("blobs").resolve("sha256").resolve(hex(digest));
    }

    private static String hex(String digest) {
        return digest.startsWith("sha256:") ? digest.substring("sha256:".length()) : digest;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> pick(List<Map<String, Object>> descriptors, String platform, String where) {
        if (descriptors.isEmpty()) {
            throw new IllegalArgumentException(where + " lists no manifests");
        }
        if (descriptors.size() == 1) {
            return descriptors.get(0);
        }
        List<String> available = new ArrayList<>();
        for (Map<String, Object> descriptor : descriptors) {
            String name = platformOf(descriptor);
            available.add(name);
            if (platform != null && !platform.isBlank() && platformMatches(name, platform)) {
                return descriptor;
            }
        }
        throw new IllegalArgumentException(where + " has " + descriptors.size() + " manifests (" + String.join(", ", available)
                + "); set platform to choose one, e.g. \"linux/amd64\"");
    }

    private static boolean platformMatches(String name, String wanted) {
        String have = name.toLowerCase(java.util.Locale.ROOT);
        String want = wanted.trim().toLowerCase(java.util.Locale.ROOT);
        return have.equals(want) || have.startsWith(want + "/") || want.startsWith(have + "/");
    }

    @SuppressWarnings("unchecked")
    private static String platformOf(Map<String, Object> descriptor) {
        if (descriptor.get("platform") instanceof Map) {
            Map<String, Object> p = (Map<String, Object>) descriptor.get("platform");
            String os = String.valueOf(p.getOrDefault("os", "?"));
            String arch = String.valueOf(p.getOrDefault("architecture", "?"));
            String variant = p.get("variant") == null ? "" : "/" + p.get("variant");
            return os + "/" + arch + variant;
        }
        return "unknown";
    }

    private static String digestOf(Object descriptor) {
        if (!(descriptor instanceof Map) || ((Map<?, ?>) descriptor).get("digest") == null) {
            throw new IllegalArgumentException("a manifest entry has no digest: " + descriptor);
        }
        return String.valueOf(((Map<?, ?>) descriptor).get("digest"));
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> descriptorList(Object raw) {
        List<Map<String, Object>> list = new ArrayList<>();
        if (raw instanceof List) {
            for (Object item : (List<Object>) raw) {
                if (item instanceof Map) {
                    list.add((Map<String, Object>) item);
                }
            }
        }
        return list;
    }

    // ------------------------------------------------------------------ legacy docker save

    @SuppressWarnings("unchecked")
    private static ImageSource fromLegacySave(Path root, Path extracted, Consumer<String> log) throws IOException {
        Object parsed = Json.parse(read(root.resolve("manifest.json")));
        if (!(parsed instanceof List) || ((List<Object>) parsed).isEmpty()) {
            throw new IllegalArgumentException("manifest.json in a docker save tarball must be a non-empty array");
        }
        Map<String, Object> entry = (Map<String, Object>) ((List<Object>) parsed).get(0);
        Path configPath = root.resolve(String.valueOf(entry.get("Config")));
        if (!Files.isRegularFile(configPath)) {
            throw new IllegalArgumentException("the image config is missing: " + entry.get("Config"));
        }
        Map<String, Path> blobs = new LinkedHashMap<>();
        String configDigest = "sha256:" + sha256Hex(configPath);
        blobs.put(configDigest, configPath);

        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("schemaVersion", 2);
        manifest.put("mediaType", MEDIA_MANIFEST);
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("mediaType", "application/vnd.docker.container.image.v1+json");
        config.put("size", Files.size(configPath));
        config.put("digest", configDigest);
        manifest.put("config", config);

        List<Object> layers = new ArrayList<>();
        List<String> layerDigests = new ArrayList<>();
        Object rawLayers = entry.get("Layers");
        if (!(rawLayers instanceof List) || ((List<Object>) rawLayers).isEmpty()) {
            throw new IllegalArgumentException("manifest.json lists no layers");
        }
        for (Object layer : (List<Object>) rawLayers) {
            Path file = root.resolve(String.valueOf(layer));
            if (!Files.isRegularFile(file)) {
                throw new IllegalArgumentException("a layer is missing: " + layer);
            }
            String digest = "sha256:" + sha256Hex(file);
            layerDigests.add(digest);
            blobs.put(digest, file);
            Map<String, Object> descriptor = new LinkedHashMap<>();
            descriptor.put("mediaType", "application/vnd.docker.image.rootfs.diff.tar");
            descriptor.put("size", Files.size(file));
            descriptor.put("digest", digest);
            layers.add(descriptor);
        }
        manifest.put("layers", layers);
        byte[] body = Json.write(manifest).getBytes(StandardCharsets.UTF_8);
        log.accept("image: legacy save, " + blobs.size() + " blobs, " + layerDigests.size() + " layers");
        return new ImageSource(body, MEDIA_MANIFEST, blobs, configDigest, layerDigests, extracted);
    }

    static final String MEDIA_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json";

    private static String sha256Hex(Path file) throws IOException {
        java.security.MessageDigest digest;
        try {
            digest = java.security.MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
        }
        return AwsSigner.hex(digest.digest());
    }

    private static String read(Path file) throws IOException {
        return Files.readString(file, StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ what the pusher needs

    byte[] manifest() {
        return manifest;
    }

    String mediaType() {
        return mediaType;
    }

    /** digest -> file, config first; each file's own bytes hash to its key. */
    Map<String, Path> blobs() {
        return blobs;
    }

    String configDigest() {
        return configDigest;
    }

    List<String> layerDigests() {
        return layerDigests;
    }

    long size() throws IOException {
        long total = 0;
        for (Path file : blobs.values()) {
            total += Files.size(file);
        }
        return total;
    }

    /** Removes the unpacked copy; a directory the caller pointed at is left alone. */
    void close() {
        if (extracted == null) {
            return;
        }
        try (var paths = Files.walk(extracted)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException ignored) {
                    // a leftover file in the temp directory is not worth failing a successful push over
                }
            });
        } catch (IOException ignored) {
            // same
        }
    }
}
