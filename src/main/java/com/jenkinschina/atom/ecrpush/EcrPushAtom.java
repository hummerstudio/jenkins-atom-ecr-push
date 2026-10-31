package com.jenkinschina.atom.ecrpush;

import com.jenkinschina.atom.sdk.AtomContext;
import com.jenkinschina.atom.sdk.AtomResult;
import com.jenkinschina.atom.sdk.AtomTask;
import com.jenkinschina.atom.sdk.ErrorType;
import com.jenkinschina.atom.sdk.Json;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pushes a container image to Amazon ECR (or any registry that speaks the Docker Registry V2 API).
 *
 * <p>The plugin this replaces built an image with the Docker daemon and pushed it through the docker CLI. Two halves,
 * and only one of them is ECR's: the build is what the {@code docker-build} atom does, the push is the registry
 * protocol. So this atom does the push half over HTTP, which is also why it can run on an agent with no daemon -- the
 * agent that most needs it. The ECR-specific work is the part people get wrong by hand: fetching a twelve-hour token
 * with a SigV4-signed {@code GetAuthorizationToken}, and treating the registry's computed digest as the truth.
 *
 * <p>Nothing here trusts a status code. After the manifest is accepted the atom asks the registry what the tag now
 * resolves to and compares it with the digest of the manifest it sent; a registry that answered 201 and stored
 * something else fails the step.
 */
public class EcrPushAtom implements AtomTask {

    private static final String ECR_SERVICE = "ecr";
    private static final String ECR_TARGET = "AmazonEC2ContainerRegistry_V20150921.GetAuthorizationToken";
    private static final Pattern ECR_HOST =
            Pattern.compile("^(\\d{12})\\.dkr\\.ecr\\.([a-z0-9-]+)\\.amazonaws\\.com(\\.cn)?$");
    private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{([A-Za-z_][A-Za-z0-9_.]*)}|\\$([A-Za-z_][A-Za-z0-9_]*)");

    @Override
    public AtomResult run(AtomContext context) throws Exception {
        String registry = context.getParam("registry", "").trim();
        String repository = context.getParam("repository", "").trim();
        String imagePath = context.getParam("image", "").trim();
        String platform = context.getParam("platform", "").trim();
        String ecrEndpoint = context.getParam("ecrEndpoint", "").trim();
        String registryEndpoint = context.getParam("registryEndpoint", "").trim();
        String region = context.getParam("region", "").trim();
        String tag = context.getParam("tag", "latest").trim();
        String extraTags = context.getParam("extraTags", "").trim();
        boolean verify = context.getBooleanParam("verifyAfterWrite", true);
        int timeoutSeconds = Math.max(5, Math.min(context.getIntParam("timeoutSeconds", 120), 3600));
        Duration timeout = Duration.ofSeconds(timeoutSeconds);

        String accessKey = secret(context, "accessKey");
        String secretKey = secret(context, "secretKey");
        String sessionToken = secret(context, "sessionToken");
        String password = secret(context, "password");
        String user = context.getParam("registryUser", "AWS").trim();

        if (registry.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40001, "registry is required (e.g. 123456789012.dkr.ecr.us-east-1.amazonaws.com)");
        }
        if (repository.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40002, "repository is required (the ECR repository name, e.g. team/app)");
        }
        if (imagePath.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40003,
                    "image is required: a docker save tarball, or an OCI layout directory");
        }

        // registryEndpoint exists for private endpoints and for tests: the host in `registry` is what ECR's domain and
        // the account id are read from, the endpoint is what the socket connects to.
        String registryBase = !registryEndpoint.isEmpty()
                ? registryEndpoint.replaceAll("/+$", "")
                : (registry.contains("://") ? registry : "https://" + registry);
        String registryHost = URI.create(registry.contains("://") ? registry : "https://" + registry).getAuthority();
        String account = "";
        Matcher host = ECR_HOST.matcher(registryHost == null ? "" : registryHost);
        if (host.matches()) {
            account = host.group(1);
            if (region.isEmpty()) {
                region = host.group(2);
            }
        }
        if (password.isEmpty()) {
            if (region.isEmpty()) {
                return AtomResult.error(ErrorType.USER, 40004,
                        "region is required to fetch an ECR token (it could not be read from the registry host)");
            }
            if (accessKey.isEmpty() || secretKey.isEmpty()) {
                return AtomResult.error(ErrorType.USER, 40005,
                        "accessKey and secretKey are required (use an AWS credential), or give a registry password");
            }
        }

        List<String> tags = new ArrayList<>();
        try {
            tags.add(expand(tag, context));
            if (!extraTags.isEmpty()) {
                for (String extra : extraTags.split(",")) {
                    String value = expand(extra.trim(), context);
                    if (!value.isEmpty() && !tags.contains(value)) {
                        tags.add(value);
                    }
                }
            }
        } catch (IllegalArgumentException e) {
            return AtomResult.error(ErrorType.USER, 40006, e.getMessage());
        }

        Path image = resolve(context, imagePath);
        ImageSource source;
        try {
            source = ImageSource.load(image, platform, context::log);
        } catch (IllegalArgumentException e) {
            return AtomResult.error(ErrorType.USER, 40007, e.getMessage());
        } catch (IOException e) {
            return AtomResult.error(ErrorType.USER, 40008, "cannot read the image at " + image + ": " + e.getMessage());
        }

        try {
            String effectiveUser = user;
            String effectivePassword = password;
            if (effectivePassword.isEmpty()) {
                String endpoint = ecrEndpoint.isEmpty()
                        ? "https://api.ecr." + region + ".amazonaws.com"
                        : ecrEndpoint.replaceAll("/+$", "");
                context.group("token");
                String[] token = authorizationToken(endpoint, region, accessKey, secretKey, sessionToken, account,
                        timeout, context);
                effectiveUser = token[0];
                effectivePassword = token[1];
                context.log("ECR issued a registry token for " + effectiveUser);
            }

            RegistryClient client = new RegistryClient(registryBase, effectiveUser, effectivePassword, timeout);
            context.group("push " + registryHost + "/" + repository);

            String localDigest = "sha256:" + AwsSigner.hex(AwsSigner.sha256(source.manifest()));
            int uploaded = 0;
            int reused = 0;
            for (Map.Entry<String, Path> blob : source.blobs().entrySet()) {
                if (client.hasBlob(repository, blob.getKey())) {
                    reused++;
                    context.log("blob " + shortDigest(blob.getKey()) + " already there");
                } else {
                    client.uploadBlob(repository, blob.getKey(), blob.getValue());
                    uploaded++;
                    context.log("blob " + shortDigest(blob.getKey()) + " uploaded ("
                            + Files.size(blob.getValue()) + " bytes)");
                }
            }

            context.group("manifest");
            String verifiedTag = "";
            for (String reference : tags) {
                String stored = client.putManifest(repository, reference, source.manifest(), source.mediaType());
                if (!stored.isEmpty() && !stored.equals(localDigest)) {
                    return AtomResult.error(ErrorType.THIRD_PART, 50201,
                            "the registry stored manifest " + stored + " but the bytes sent hash to " + localDigest);
                }
                context.log(reference + " -> " + localDigest);
                if (verify) {
                    String readBack = client.headManifest(repository, reference);
                    if (readBack == null) {
                        return AtomResult.error(ErrorType.THIRD_PART, 50202,
                                "the registry accepted the manifest for " + reference + " and then has no such tag");
                    }
                    if (!readBack.isEmpty() && !readBack.equals(localDigest)) {
                        return AtomResult.error(ErrorType.THIRD_PART, 50203,
                                reference + " reads back as " + readBack + " instead of " + localDigest);
                    }
                    verifiedTag = reference;
                }
            }

            AtomResult result = AtomResult.success("pushed " + registryHost + "/" + repository + ":"
                    + String.join(",", tags) + " (" + localDigest + ")");
            result.data("repository", repository)
                    .data("registry", registryHost)
                    .data("tag", tags.get(0))
                    .data("tags", String.join(",", tags))
                    .data("digest", localDigest)
                    .data("blobsUploaded", String.valueOf(uploaded))
                    .data("blobsReused", String.valueOf(reused))
                    .data("imageSizeBytes", String.valueOf(source.size()))
                    .data("manifestMediaType", source.mediaType())
                    .data("verified", verify ? String.valueOf(!verifiedTag.isEmpty()) : "false");
            return result;
        } catch (RegistryClient.RegistryError e) {
            return registryFailure(e, registryHost, repository);
        } catch (EcrApiError e) {
            return e.type == ErrorType.USER
                    ? AtomResult.error(ErrorType.USER, 40020, e.getMessage())
                    : AtomResult.error(ErrorType.THIRD_PART, 50200, e.getMessage());
        } catch (IOException e) {
            return AtomResult.error(ErrorType.THIRD_PART, 50204,
                    "cannot reach " + registryHost + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
        } finally {
            source.close();
        }
    }

    // ------------------------------------------------------------------ ECR auth

    /**
     * {@code GetAuthorizationToken}: a signed JSON POST that answers with base64 {@code AWS:<password>}. The registry
     * wants that pair as HTTP Basic -- which is why a wrong signature shows up here as a plain 403 rather than as a
     * confusing 401 from the registry later.
     */
    private String[] authorizationToken(String endpoint, String region, String accessKey, String secretKey,
                                        String sessionToken, String account, Duration timeout, AtomContext context)
            throws IOException, InterruptedException, EcrApiError {
        String body = account.isEmpty() ? "{}" : "{\"registryIds\":[\"" + account + "\"]}";
        String host = URI.create(endpoint).getAuthority();
        Map<String, String> signed = new LinkedHashMap<>();
        signed.put("content-type", "application/x-amz-json-1.1");
        signed.put("x-amz-target", ECR_TARGET);
        Map<String, String> headers = new AwsSigner(accessKey, secretKey, sessionToken, region, ECR_SERVICE)
                .headers("POST", "/", "", body, host, signed);

        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(endpoint + "/"))
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        headers.forEach(request::header);

        HttpResponse<String> reply = HttpClient.newBuilder().connectTimeout(timeout).build()
                .send(request.build(), HttpResponse.BodyHandlers.ofString());
        if (reply.statusCode() != 200) {
            throw EcrApiError.from(reply.statusCode(), reply.body());
        }
        Object parsed = Json.parse(reply.body());
        if (!(parsed instanceof Map)) {
            throw new EcrApiError(ErrorType.THIRD_PART, "GetAuthorizationToken answered something that is not an object");
        }
        Object data = ((Map<?, ?>) parsed).get("authorizationData");
        if (!(data instanceof List) || ((List<?>) data).isEmpty()) {
            throw new EcrApiError(ErrorType.THIRD_PART, "GetAuthorizationToken returned no authorizationData");
        }
        Object token = ((Map<?, ?>) ((List<?>) data).get(0)).get("authorizationToken");
        if (token == null) {
            throw new EcrApiError(ErrorType.THIRD_PART, "the token response has no authorizationToken");
        }
        String decoded = new String(Base64.getDecoder().decode(String.valueOf(token)), StandardCharsets.UTF_8);
        int colon = decoded.indexOf(':');
        if (colon < 0) {
            throw new EcrApiError(ErrorType.THIRD_PART,
                    "the token is not base64 of user:password (" + decoded.length() + " characters decoded)");
        }
        context.log("token scope: " + decoded.substring(0, colon));
        return new String[]{decoded.substring(0, colon), decoded.substring(colon + 1)};
    }

    /** An ECR API answered with an error document: {@code __type} plus a message. */
    static final class EcrApiError extends Exception {
        final ErrorType type;

        EcrApiError(ErrorType type, String message) {
            super(message);
            this.type = type;
        }

        static EcrApiError from(int status, String body) {
            String code = "";
            String message = "";
            try {
                Object parsed = Json.parse(body);
                if (parsed instanceof Map) {
                    Map<?, ?> map = (Map<?, ?>) parsed;
                    code = map.get("__type") == null ? "" : String.valueOf(map.get("__type"));
                    if (code.contains("#")) {
                        code = code.substring(code.lastIndexOf('#') + 1);
                    }
                    if (map.get("message") != null) {
                        message = String.valueOf(map.get("message"));
                    } else if (map.get("Message") != null) {
                        message = String.valueOf(map.get("Message"));
                    }
                }
            } catch (RuntimeException ignored) {
                message = body;
            }
            boolean mine = status == 400 || status == 401 || status == 403
                    || code.contains("AccessDenied") || code.contains("InvalidSignature")
                    || code.contains("UnrecognizedClient") || code.contains("ExpiredToken");
            String text = "ECR answered " + status + (code.isEmpty() ? "" : " " + code)
                    + (message.isBlank() ? "" : ": " + message);
            if (mine) {
                text += " (check the AWS credential and the agent clock: SigV4 is time-sensitive)";
            }
            return new EcrApiError(mine ? ErrorType.USER : ErrorType.THIRD_PART, text);
        }
    }

    // ------------------------------------------------------------------ helpers

    private AtomResult registryFailure(RegistryClient.RegistryError e, String host, String repository) {
        String body = e.body;
        if (e.status == 401 || e.status == 403) {
            return AtomResult.error(ErrorType.USER, 40030,
                    "the registry rejected the token for " + host + "/" + repository + " (" + e.status + "): " + body);
        }
        if (e.status == 404 || body.contains("NAME_UNKNOWN")) {
            return AtomResult.error(ErrorType.USER, 40031,
                    "ECR has no repository " + repository + " (or the blob/manifest is missing): " + body
                            + " -- create it first with `aws ecr create-repository`");
        }
        if (e.status == 400) {
            return AtomResult.error(ErrorType.THIRD_PART, 50205,
                    "the registry refused the upload: " + body);
        }
        return AtomResult.error(ErrorType.THIRD_PART, 50206, "the registry failed: " + e.getMessage());
    }

    private static String secret(AtomContext context, String name) {
        String value = context.getSecret(name);
        if (value == null) {
            value = context.getParam(name, "");
        }
        return value == null ? "" : value.trim();
    }

    private static Path resolve(AtomContext context, String path) {
        Path candidate = Paths.get(path);
        return candidate.isAbsolute() ? candidate : context.getWorkspace().resolve(candidate);
    }

    /**
     * Expands {@code $BUILD_NUMBER} / {@code ${BUILD_NUMBER}} in a tag. Jenkins users write tags that way, and a tag
     * with an unexpanded placeholder would push a literal {@code $BUILD_NUMBER} image that nobody looks for again.
     */
    private static String expand(String value, AtomContext context) {
        Matcher matcher = PLACEHOLDER.matcher(value);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String name = matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
            String replacement = context.getParam(name);
            if (replacement == null || replacement.isEmpty()) {
                throw new IllegalArgumentException("tag " + value + " refers to ${" + name + "}, which is not set");
            }
            matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(out);
        String expanded = out.toString();
        if (expanded.contains("$")) {
            throw new IllegalArgumentException("tag " + value + " still contains a '$' after expansion");
        }
        return expanded;
    }

    private static String shortDigest(String digest) {
        String hex = digest.startsWith("sha256:") ? digest.substring(7) : digest;
        return "sha256:" + hex.substring(0, Math.min(12, hex.length()));
    }
}
