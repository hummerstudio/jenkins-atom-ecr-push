package atom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jenkinschina.atom.sdk.Json;
import com.jenkinschina.atom.sdk.testing.Atom;
import com.jenkinschina.atom.sdk.testing.AtomResult;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The ecr-push atom, started the way the runner starts it, against the fixtures in {@code tools/}.
 *
 * <p>The images are built by {@code mk_image.py} — real OCI layouts and a real legacy docker save — and the registry's
 * storage and wire log are read back by {@code checkimage.py} and {@code wire.py}, so the assertions compare the atom's
 * output with bytes it never wrote. The fake ECR recomputes the SigV4 signature and verifies every blob against the
 * digest in its URL; the defect flags are the same server with one thing broken.
 */
class EcrPushIT {

    private static final String REGISTRY = "123456789012.dkr.ecr.us-east-1.amazonaws.com";
    private static final String LAYER = "{\"app/amd64.txt\": \"pushed by ecr-push\\namd64\\n\"}";
    private static final String ARM_LAYER = "{\"app/arm64.txt\": \"pushed by ecr-push\\narm64\\n\"}";

    private static Path fixtures;
    private static String oci;
    private static String ociImage;
    private static String legacyImage;
    private static String tarImage;
    private static String legacy;
    private static String mAmd;
    private static String mArm;
    private static String cAmd;
    private static String lAmd;
    private static String lArm;
    private static String cLeg;
    private static String lLeg;

    private Atom atom;
    private Process server;
    private Path state;
    private Path wirelog;
    private String api;
    private String registry;

    @BeforeAll
    static void buildImages() throws Exception {
        fixtures = Files.createTempDirectory(Path.of(System.getProperty("atom.scratch")), "images-");
        ociImage = fixtures.resolve("oci").toString();
        oci = py("tools/mk_image.py", "oci", ociImage);
        legacyImage = fixtures.resolve("legacy").toString();
        legacy = py("tools/mk_image.py", "legacy", legacyImage);
        tarImage = fixtures.resolve("image.tar").toString();
        py("tools/mk_image.py", "oci-tar", tarImage);

        mAmd = fact(oci, "amd64", "manifest");
        mArm = fact(oci, "arm64", "manifest");
        cAmd = fact(oci, "amd64", "config");
        lAmd = fact(oci, "amd64", "layer");
        lArm = fact(oci, "arm64", "layer");
        cLeg = fact(legacy, "amd64", "config");
        lLeg = fact(legacy, "amd64", "layer");
    }

    @BeforeEach
    void setUp() throws Exception {
        atom = Atom.of();
    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.destroy();
            server = null;
        }
    }

    // ---------------------------------------------------------------- fixtures and the fake registry

    private static String fact(String image, String platform, String field) {
        Object platforms = Json.parseObject(image).get("platforms");
        Object entry = platforms instanceof Map<?, ?> map ? map.get(platform) : null;
        return String.valueOf(entry instanceof Map<?, ?> map ? map.get(field) : "");
    }

    /** One fresh fake ECR: empty storage, empty wire log, the same defect flags the smoke restarted with. */
    private void start(String... flags) throws Exception {
        if (server != null) {
            server.destroy();
            server = null;
        }
        int apiPort;
        int registryPort;
        try (ServerSocket first = new ServerSocket(0); ServerSocket second = new ServerSocket(0)) {
            apiPort = first.getLocalPort();
            registryPort = second.getLocalPort();
        }
        state = Files.createDirectories(
                Path.of(System.getProperty("atom.scratch")).resolve("ecr-state-" + System.nanoTime()));
        wirelog = state.resolve("wire.log");
        api = "http://127.0.0.1:" + apiPort;
        registry = "http://127.0.0.1:" + registryPort;

        List<String> command = new ArrayList<>(List.of("python3",
                Path.of(System.getProperty("atom.module")).resolve("tools/fake_ecr.py").toString(),
                String.valueOf(apiPort), String.valueOf(registryPort), state.toString(), wirelog.toString()));
        command.addAll(List.of(flags));
        server = new ProcessBuilder(command).redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(state.resolve("server.out").toFile()))
                .start();
        for (int attempt = 0; attempt < 200; attempt++) {
            if (reachable(apiPort) && reachable(registryPort)) {
                return;
            }
            Thread.sleep(100);
        }
        throw new IllegalStateException("the fake ECR did not start");
    }

    private static boolean reachable(int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", port), 200);
            return true;
        } catch (IOException notYet) {
            return false;
        }
    }

    // ---------------------------------------------------------------- the run

    private AtomResult push(String extra, String secrets, String image) throws Exception {
        Map<String, Object> given = new LinkedHashMap<>();
        given.put("registry", REGISTRY);
        given.put("registryEndpoint", registry);
        given.put("ecrEndpoint", api);
        given.put("region", "us-east-1");
        given.put("repository", "team/app");
        given.put("tag", "1.0.0");
        given.put("image", image);
        given.put("platform", "linux/amd64");
        given.put("verifyAfterWrite", "true");
        given.put("timeoutSeconds", "20");
        given.put("BUILD_NUMBER", "77");
        given.putAll(Json.parseObject(extra));
        String credentials = secrets.isEmpty()
                ? "{\"accessKey\": \"AKIAEXAMPLEKEY0001\", \"secretKey\": \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"}"
                : secrets;
        return atom.input(Json.write(given)).file(".secrets.json", credentials).run();
    }

    private AtomResult push(String extra) throws Exception {
        return push(extra, "", ociImage);
    }

    // ---------------------------------------------------------------- reading the tools back

    private static String py(String... args) throws Exception {
        List<String> command = new ArrayList<>(List.of("python3"));
        Path module = Path.of(System.getProperty("atom.module"));
        command.add(module.resolve(Path.of(args[0])).toString());
        command.addAll(List.of(args).subList(1, args.length));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
        assertEquals(0, process.waitFor(), "python3 " + String.join(" ", args) + " failed:\n" + output);
        return output;
    }

    private String served(String needle) throws Exception {
        return py("tools/wire.py", wirelog.toString(), needle);
    }

    private int count(String needle) throws Exception {
        if (!Files.isRegularFile(wirelog)) {
            return 0;
        }
        String output = served(needle);
        return output.isBlank() ? 0 : output.split("\n").length;
    }

    private String manifest(String reference) throws Exception {
        return py("tools/checkimage.py", "manifest", state.toString(), "team/app", reference);
    }

    private String blob(String digest) throws Exception {
        return py("tools/checkimage.py", "blob", state.toString(), digest);
    }

    private String layer(String digest) throws Exception {
        return py("tools/checkimage.py", "layer", state.toString(), digest);
    }

    private long blobs() throws IOException {
        Path dir = state.resolve("blobs");
        if (!Files.isDirectory(dir)) {
            return 0;
        }
        try (var list = Files.list(dir)) {
            return list.count();
        }
    }

    /** {@code jget}: a dotted path through the manifest JSON, with numeric indexes for lists. */
    private static String at(String json, String path) {
        Object node = Json.parseObject(json);
        for (String part : path.split("\\.")) {
            if (node instanceof Map<?, ?> map) {
                node = map.get(part);
            } else if (node instanceof List<?> list && part.chars().allMatch(Character::isDigit)) {
                int index = Integer.parseInt(part);
                node = index < list.size() ? list.get(index) : null;
            } else {
                return "";
            }
        }
        return node == null ? "" : String.valueOf(node);
    }

    // ---------------------------------------------------------------- the real push

    @Test
    @DisplayName("an OCI layout, one platform out of two: two blobs, a verified push, and the right digest")
    void pushesOnePlatformOfAnOciLayout() throws Exception {
        start();
        AtomResult run = push("{\"tag\": \"1.0.0\", \"platform\": \"linux/amd64\"}");

        run.assertOk();
        assertEquals(mAmd, run.field("digest"));
        assertEquals("2", run.field("blobsUploaded"), "two blobs (config + layer) should be new");
        assertEquals("0", run.field("blobsReused"), "nothing was there yet");
        assertEquals("true", run.field("verified"), "the push must be read back");
        assertEquals("1.0.0", run.field("tag"));
        assertEquals(REGISTRY, run.field("registry"));

        // the token call: signed, pointed at the right operation, asking for this account's registry
        assertEquals(1, count("AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken"),
                "the token call carried the wrong X-Amz-Target");
        assertEquals(1, count("\"signed_ok\": true"), "the signature did not verify");
        assertEquals(1, count("registryIds"), "the token request must ask for the account's registry");
        assertTrue(count("\"authorization\": \"Basic ") > 0, "the registry calls must use the issued token");

        // what the registry actually holds
        assertEquals(cAmd, blob(cAmd), "the config blob does not hash to its digest");
        assertEquals(lAmd, blob(lAmd), "the layer blob does not hash to its digest");
        String stored = manifest("1.0.0");
        assertEquals(mAmd, at(stored, "digest"), "the tag points at the wrong digest");
        assertEquals(mAmd, at(stored, "sha256"), "the stored manifest is not the one that was sent");
        assertEquals(cAmd, at(stored, "json.config.digest"), "the stored manifest names the wrong config");
        assertEquals(LAYER, layer(lAmd), "the layer inside the registry is not the layer that was built");
    }

    @Test
    @DisplayName("pushing the same image again uploads nothing and opens no upload session")
    void reusesTheBlobsOnASecondPush() throws Exception {
        start();
        push("{\"tag\": \"1.0.0\", \"platform\": \"linux/amd64\"}").assertOk();
        int uploadsBefore = count("blobs/uploads");

        AtomResult run = push("{\"tag\": \"1.0.1\", \"platform\": \"linux/amd64\"}");

        run.assertOk();
        assertEquals("0", run.field("blobsUploaded"), "a re-push must reuse the blobs");
        assertEquals("2", run.field("blobsReused"), "both blobs were already there");
        assertEquals(uploadsBefore, count("blobs/uploads"), "a re-push must not open an upload session");
    }

    @Test
    @DisplayName("a different platform out of the same list is the other manifest and layer")
    void pushesTheOtherPlatform() throws Exception {
        start();
        AtomResult run = push("{\"tag\": \"arm\", \"platform\": \"linux/arm64\"}");

        run.assertOk();
        assertEquals(mArm, run.field("digest"));
        assertEquals(lArm, blob(lArm), "the arm64 layer is missing");
        assertEquals(ARM_LAYER, layer(lArm), "the arm64 layer holds the wrong file");
    }

    @Test
    @DisplayName("a multi-platform image without a platform is refused before anything is pushed")
    void refusesAMultiPlatformImageWithoutAPlatform() throws Exception {
        start();
        long before = blobs();
        AtomResult run = push("{\"tag\": \"wrong\", \"platform\": \"\"}");

        run.assertRefused();
        assertEquals("40007", run.field("errorCode"), "that is a USER input problem");
        assertTrue(run.field("message").contains("linux/amd64, linux/arm64"),
                "the message must list what is there: " + run.field("message"));
        assertEquals(before, blobs(), "a refused input must not upload anything");
    }

    @Test
    @DisplayName("a docker save tar (an OCI layout in a tarball) is pushed like the directory")
    void pushesAnOciTarball() throws Exception {
        start();
        AtomResult run = push("{\"tag\": \"tar\", \"platform\": \"linux/amd64\"}", "", tarImage);

        run.assertOk();
        assertEquals(mAmd, run.field("digest"));
        assertEquals(mAmd, at(manifest("tar"), "digest"), "the tarball's manifest landed under the wrong digest");
    }

    @Test
    @DisplayName("a legacy docker save: the atom writes the schema-2 manifest itself")
    void writesTheManifestForALegacySave() throws Exception {
        start();
        AtomResult run = push("{\"tag\": \"legacy\"}", "", legacyImage);

        run.assertOk();
        String stored = manifest("legacy");
        assertEquals(cLeg, at(stored, "json.config.digest"), "the generated manifest names the wrong config");
        assertEquals(lLeg, at(stored, "json.layers.0.digest"), "the generated manifest names the wrong layer");
        assertEquals("application/vnd.docker.distribution.manifest.v2+json", at(stored, "json.mediaType"),
                "a legacy save pushes a docker manifest");
        assertEquals(at(stored, "sha256"), at(stored, "digest"),
                "the digest the registry reports is the digest of the manifest it stored");
        assertEquals(at(stored, "digest"), run.field("digest"), "the output digest is what the registry has");
        assertEquals(LAYER, layer(lLeg), "the legacy layer arrived intact");
    }

    @Test
    @DisplayName("a tag expands from $BUILD_NUMBER, and an unset variable is refused before the token call")
    void expandsTheTag() throws Exception {
        start();
        AtomResult run = push("{\"tag\": \"1.0.$BUILD_NUMBER\", \"platform\": \"linux/amd64\"}");

        run.assertOk();
        assertEquals("1.0.77", run.field("tag"), "the tag must be expanded");
        manifest("1.0.77");

        int tokens = count("GetAuthorizationToken");
        AtomResult unset = push("{\"tag\": \"1.0.$NOT_SET\", \"platform\": \"linux/amd64\"}");
        unset.assertRefused();
        assertTrue(unset.field("message").contains("not set"),
                "the message must name the missing variable: " + unset.field("message"));
        assertEquals(tokens, count("GetAuthorizationToken"), "a bad input must not fetch a token");
    }

    @Test
    @DisplayName("extraTags pushes each extra tag and lists them")
    void pushesExtraTags() throws Exception {
        start();
        AtomResult run = push("{\"tag\": \"multi\", \"extraTags\": \"latest, multi\","
                + " \"platform\": \"linux/amd64\"}");

        run.assertOk();
        assertEquals("multi,latest", run.field("tags"));
        manifest("latest");
    }

    // ---------------------------------------------------------------- the registry's defects

    @Test
    @DisplayName("a registry that stores a different manifest is caught by the read-back")
    void catchesARegistryThatStoresAnotherManifest() throws Exception {
        start("--drop-manifests");
        AtomResult run = push("{\"tag\": \"liar\", \"platform\": \"linux/amd64\"}");

        run.assertRefused();
        assertTrue(run.field("message").contains("reads back as"),
                "the read-back has to catch it: " + run.field("message"));
        assertEquals("50203", run.field("errorCode"), "a lying registry is THIRD_PART");
    }

    @Test
    @DisplayName("a registry that reports a digest it did not store is caught")
    void catchesADisagreeingDigest() throws Exception {
        start("--wrong-put-digest");
        AtomResult run = push("{\"tag\": \"shifted\", \"platform\": \"linux/amd64\"}");

        run.assertRefused();
        assertTrue(run.field("message").contains("the bytes sent hash to"),
                "the message: " + run.field("message"));
        assertEquals("50201", run.field("errorCode"), "a disagreeing digest is THIRD_PART");
    }

    @Test
    @DisplayName("AccessDenied on the token is a user problem and the AWS error is passed through")
    void reportsAccessDenied() throws Exception {
        start("--deny");
        AtomResult run = push("{\"tag\": \"denied\", \"platform\": \"linux/amd64\"}");

        run.assertRefused();
        assertTrue(run.field("message").contains("AccessDeniedException"),
                "the AWS error must be passed through: " + run.field("message"));
        assertEquals("40020", run.field("errorCode"), "a refused credential is the user's problem");
    }

    @Test
    @DisplayName("a wrong secret key is a user problem and the message says the signature")
    void reportsAWrongSecretKey() throws Exception {
        start();
        AtomResult run = push("{\"tag\": \"badkey\", \"platform\": \"linux/amd64\"}",
                "{\"accessKey\": \"AKIAEXAMPLEKEY0001\", \"secretKey\": \"wrong-secret\"}", ociImage);

        run.assertRefused();
        assertEquals("40020", run.field("errorCode"), "a rejected signature is the user's problem");
        assertTrue(run.field("message").contains("signature"),
                "the message has to say the signature: " + run.field("message"));
    }

    @Test
    @DisplayName("an expired registry token is a credential problem")
    void reportsAnExpiredToken() throws Exception {
        start("--expire");
        AtomResult run = push("{\"tag\": \"expired\", \"platform\": \"linux/amd64\"}");

        run.assertRefused();
        assertTrue(run.field("message").contains("rejected the token"), "the message: " + run.field("message"));
        assertEquals("40030", run.field("errorCode"), "401 at the registry is a credential problem");
    }

    @Test
    @DisplayName("a repository that does not exist is named, with what to do about it")
    void reportsAMissingRepository() throws Exception {
        start("--only-repo=team/other");
        AtomResult run = push("{\"tag\": \"norepo\", \"platform\": \"linux/amd64\"}");

        run.assertRefused();
        assertTrue(run.field("message").contains("no repository team/app"),
                "the message must name the repository: " + run.field("message"));
        assertTrue(run.field("message").contains("create-repository"),
                "and say what to do: " + run.field("message"));
    }

    @Test
    @DisplayName("a registry that refuses the blob upload is a third-party error")
    void reportsARejectedBlob() throws Exception {
        start("--reject-blobs", "--hide-blobs");
        AtomResult run = push("{\"tag\": \"reject\", \"platform\": \"linux/amd64\"}");

        run.assertRefused();
        assertEquals("50205", run.field("errorCode"), "a refused upload is THIRD_PART");
    }

    @Test
    @DisplayName("a missing image path is a user problem, before the registry is touched")
    void refusesAMissingImage() throws Exception {
        start();
        AtomResult run = push("{\"tag\": \"missing\", \"platform\": \"linux/amd64\"}", "",
                fixtures.resolve("does-not-exist").toString());

        run.assertRefused();
        assertEquals("40007", run.field("errorCode"), "a missing image path is USER");
        assertTrue(run.field("message").contains("image not found"), "the message: " + run.field("message"));
        assertEquals(0, count("GetAuthorizationToken"), "a missing image must not call the registry");
    }
}
