package com.jenkinschina.atom.ecrpush;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.GZIPInputStream;

/**
 * A tar reader that does what a container image tarball needs and nothing else.
 *
 * <p>{@code docker save} writes a plain tar (sometimes gzipped) whose entries are the image's files; to push it we only
 * have to get those files out onto disk, because from there the blobs are content-addressed by their own bytes. So this
 * reads ustar headers, follows GNU long names and pax {@code path=} records, and refuses entries that try to escape the
 * extraction directory -- a tarball from a build is still input from somewhere else.
 */
final class TarReader {

    private TarReader() {
    }

    /** Extracts every regular file into {@code dest}, returning the number of entries written. */
    static int extract(Path archive, Path dest) throws IOException {
        Files.createDirectories(dest);
        try (InputStream raw = Files.newInputStream(archive)) {
            InputStream in = maybeGzip(raw);
            return extract(in, dest);
        }
    }

    private static InputStream maybeGzip(InputStream raw) throws IOException {
        BufferedInputStream buffered = new BufferedInputStream(raw);
        buffered.mark(2);
        int first = buffered.read();
        int second = buffered.read();
        buffered.reset();
        return first == 0x1f && second == 0x8b ? new GZIPInputStream(buffered) : buffered;
    }

    static int extract(InputStream in, Path dest) throws IOException {
        byte[] header = new byte[512];
        String longName = null;
        int written = 0;
        while (true) {
            if (!readFully(in, header)) {
                return written;
            }
            if (isZero(header)) {
                return written;
            }
            String name = string(header, 0, 100);
            String sizeField = string(header, 124, 12).trim();
            byte type = header[156];
            String prefix = string(header, 345, 155);
            long size = sizeField.isEmpty() ? 0 : Long.parseLong(sizeField, 8);
            if (!prefix.isEmpty() && type != 'L' && type != 'x' && type != 'g') {
                name = prefix + "/" + name;
            }

            if (type == 'L') {                        // GNU long name: the next header's name
                byte[] longBytes = readBody(in, size);
                longName = string(longBytes, 0, longBytes.length).replace("\0", "").trim();
                continue;
            }
            if (type == 'x' || type == 'g') {          // pax extended header
                byte[] pax = readBody(in, size);
                String path = paxPath(pax);
                if (path != null) {
                    longName = path;
                }
                continue;
            }
            if (longName != null) {
                name = longName;
                longName = null;
            }

            if (type == '0' || type == 0) {
                Path target = safeResolve(dest, name);
                if (target != null) {
                    Files.createDirectories(target.getParent());
                    try (OutputStream out = Files.newOutputStream(target)) {
                        copy(in, out, size);
                        written++;
                    }
                } else {
                    skip(in, size);
                }
            } else {
                skip(in, size);
            }
        }
    }

    private static String paxPath(byte[] pax) {
        String text = new String(pax, StandardCharsets.UTF_8);
        for (String line : text.split("\n")) {
            int space = line.indexOf(' ');
            if (space > 0 && line.substring(space + 1).startsWith("path=")) {
                return line.substring(space + 1 + "path=".length());
            }
        }
        return null;
    }

    /** null when the entry would land outside {@code dest}; the caller skips the body instead. */
    private static Path safeResolve(Path dest, String name) throws IOException {
        Path root = dest.toAbsolutePath().normalize();
        Path target = root.resolve(name.replaceFirst("^/+", "")).normalize();
        return target.startsWith(root) ? target : null;
    }

    private static byte[] readBody(InputStream in, long size) throws IOException {
        if (size > 16L * 1024 * 1024) {
            throw new IOException("tar entry is too large for a header record: " + size);
        }
        byte[] body = new byte[(int) size];
        readFully(in, body);
        skip(in, padding(size));
        return body;
    }

    private static void copy(InputStream in, OutputStream out, long size) throws IOException {
        byte[] buffer = new byte[64 * 1024];
        long left = size;
        while (left > 0) {
            int read = in.read(buffer, 0, (int) Math.min(buffer.length, left));
            if (read < 0) {
                throw new EOFException("tar entry ended " + left + " bytes early");
            }
            out.write(buffer, 0, read);
            left -= read;
        }
        skip(in, padding(size));
    }

    private static long padding(long size) {
        long remainder = size % 512;
        return remainder == 0 ? 0 : 512 - remainder;
    }

    private static void skip(InputStream in, long count) throws IOException {
        long left = count;
        while (left > 0) {
            long skipped = in.skip(left);
            if (skipped <= 0) {
                if (in.read() < 0) {
                    throw new EOFException("tar is truncated");
                }
                skipped = 1;
            }
            left -= skipped;
        }
    }

    private static boolean readFully(InputStream in, byte[] buffer) throws IOException {
        int read = 0;
        while (read < buffer.length) {
            int n = in.read(buffer, read, buffer.length - read);
            if (n < 0) {
                return read > 0 && !isZero(buffer);
            }
            read += n;
        }
        return true;
    }

    private static boolean isZero(byte[] block) {
        for (byte value : block) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

    private static String string(byte[] block, int offset, int length) {
        int end = offset;
        while (end < offset + length && block[end] != 0) {
            end++;
        }
        return new String(block, offset, end - offset, StandardCharsets.UTF_8);
    }
}
