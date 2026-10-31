package com.jenkinschina.atom.ecrpush;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

/**
 * The Docker Registry HTTP API V2, the part a push uses.
 *
 * <p>This is deliberately not the docker CLI. ECR's registry speaks the same protocol every other registry speaks,
 * so pushing with four HTTP calls means the step works on an agent that has no daemon, no privileged socket and no
 * docker binary at all -- which is exactly the agent that cannot run the original plugin. It also means the wire is
 * testable.
 *
 * <p>Auth is HTTP Basic with the password ECR hands out as a base64 {@code AWS:<token>}; that token is good for
 * twelve hours, which is why it is fetched per build rather than configured.
 */
final class RegistryClient {

    /** A registry said no, with enough of the answer to explain it. */
    static final class RegistryError extends Exception {
        final int status;
        final String body;

        RegistryError(int status, String body) {
            super("registry answered " + status + (body == null || body.isBlank() ? "" : ": " + body));
            this.status = status;
            this.body = body == null ? "" : body;
        }
    }

    private final String base;
    private final String authorization;
    private final HttpClient client;
    private final Duration timeout;

    RegistryClient(String base, String user, String password, Duration timeout) {
        this.base = base.replaceAll("/+$", "");
        this.timeout = timeout;
        this.authorization = "Basic " + Base64.getEncoder()
                .encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
        this.client = HttpClient.newBuilder().connectTimeout(timeout).build();
    }

    /** True when the registry already has this blob, so a re-push of the same image uploads nothing. */
    boolean hasBlob(String repository, String digest) throws IOException, RegistryError, InterruptedException {
        HttpResponse<String> reply = send(base + "/v2/" + repository + "/blobs/" + digest, "HEAD", null, null, null);
        if (reply.statusCode() == 200) {
            return true;
        }
        if (reply.statusCode() == 404) {
            return false;
        }
        throw new RegistryError(reply.statusCode(), reply.body());
    }

    /**
     * Uploads one blob: POST opens a session, PUT finishes it with the digest the registry has to verify against the
     * bytes it just received. A registry that stores something else answers 400, which is the point of the digest.
     */
    void uploadBlob(String repository, String digest, Path file) throws IOException, RegistryError, InterruptedException {
        HttpResponse<String> opened = send(base + "/v2/" + repository + "/blobs/uploads/", "POST", null, null, "");
        if (opened.statusCode() != 202 && opened.statusCode() != 201) {
            throw new RegistryError(opened.statusCode(), opened.body());
        }
        if (opened.statusCode() == 201) {
            return;                // already there, the registry says so
        }
        String location = header(opened, "Location")
                .orElseThrow(() -> new RegistryError(opened.statusCode(), "202 with no Location header"));
        String target = location.startsWith("http") ? location : base + location;
        String separator = target.contains("?") ? "&" : "?";
        String finish = target + separator + "digest=" + URLEncoder.encode(digest, StandardCharsets.UTF_8);

        HttpRequest request = HttpRequest.newBuilder(URI.create(finish))
                .timeout(timeout)
                .header("Authorization", authorization)
                .header("Content-Type", "application/octet-stream")
                .PUT(HttpRequest.BodyPublishers.ofFile(file))
                .build();
        HttpResponse<String> done = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (done.statusCode() != 201 && done.statusCode() != 204) {
            throw new RegistryError(done.statusCode(), done.body());
        }
        String stored = header(done, "Docker-Content-Digest").orElse(digest);
        if (!stored.equals(digest)) {
            throw new RegistryError(done.statusCode(), "the registry stored " + stored + " instead of " + digest);
        }
    }

    /** Puts the manifest under one tag and returns the digest the registry computed for it. */
    String putManifest(String repository, String reference, byte[] manifest, String mediaType)
            throws IOException, RegistryError, InterruptedException {
        HttpResponse<String> reply = send(base + "/v2/" + repository + "/manifests/" + reference, "PUT",
                mediaType, manifest, null);
        if (reply.statusCode() != 201 && reply.statusCode() != 200 && reply.statusCode() != 202) {
            throw new RegistryError(reply.statusCode(), reply.body());
        }
        return header(reply, "Docker-Content-Digest").orElse("");
    }

    /** The digest the tag resolves to right now, or null when the tag is not there. */
    String headManifest(String repository, String reference)
            throws IOException, RegistryError, InterruptedException {
        HttpResponse<String> reply = send(base + "/v2/" + repository + "/manifests/" + reference, "HEAD", null, null, null);
        if (reply.statusCode() == 404) {
            return null;
        }
        if (reply.statusCode() != 200) {
            throw new RegistryError(reply.statusCode(), reply.body());
        }
        return header(reply, "Docker-Content-Digest").orElse("");
    }

    private HttpResponse<String> send(String url, String method, String contentType, byte[] body, String emptyBody)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("Authorization", authorization)
                .header("Accept", ImageSource.MEDIA_MANIFEST
                        + ", application/vnd.oci.image.manifest.v1+json, */*");
        if (contentType != null) {
            builder.header("Content-Type", contentType);
        }
        if ("HEAD".equals(method)) {
            builder.method("HEAD", HttpRequest.BodyPublishers.noBody());
        } else if (body != null) {
            builder.method(method, HttpRequest.BodyPublishers.ofByteArray(body));
        } else {
            builder.method(method, emptyBody == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofString(emptyBody));
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static Optional<String> header(HttpResponse<?> reply, String name) {
        return reply.headers().firstValue(name);
    }

    /** Reads a blob back, for the verification step; the caller closes it. */
    static InputStream open(Path file) throws IOException {
        return Files.newInputStream(file);
    }
}
