package gearth.app.protocol.connection.proxy.unity.standalone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Properties;
import java.util.UUID;

final class UnityStandaloneClient {

    private static final Logger LOG = LoggerFactory.getLogger(UnityStandaloneClient.class);
    private static final HexFormat HEX = HexFormat.of();
    private static final String CACHE_FORMAT = "3";
    private static final byte[] ORIGINAL_TEMPLATE = "wss://{0}:{1}/websocket".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LOCAL_TEMPLATE = "wss://127.0.0.1:{1}/{0}".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] ACCEPT_CERTIFICATE = HEX.parseHex("b801000000c3");
    private static final byte[] CERTIFICATE_VERIFIER_PREFIX = HEX.parseHex("558bec51803d");
    private static final int CERTIFICATE_VERIFIER_BODY_OFFSET = 0x35;
    private static final MaskedPattern CERTIFICATE_VERIFIER_BODY = MaskedPattern.compile("""
            8B 45 08 85 C0 0F 84 ?? ?? ?? ?? 53 56 57 6A 00 6A 00 6A 03 50 E8 ?? ?? ?? ??
            6A 00 50 89 45 FC E8 ?? ?? ?? ?? 83 C4 18 84 C0 0F 85 ?? ?? ?? ?? 8B 5D 0C 85
            DB 0F 84 ?? ?? ?? ?? 8B 03 33 FF 8B 35 ?? ?? ?? ?? 33 C9 0F B7 90 B6 00 00 00
            66 3B FA
            """);

    private final Path cacheDirectory;

    UnityStandaloneClient(Path cacheDirectory) {
        this.cacheDirectory = cacheDirectory.toAbsolutePath().normalize();
    }

    PreparedClient prepare() throws Exception {
        Files.createDirectories(cacheDirectory);
        ClientSource client = findClient();
        KeyPair keyPair = loadOrCreateKeys(cacheDirectory.resolve("keys"));
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String modulus = publicKey.getModulus().toString(16).toUpperCase();
        Path clients = cacheDirectory.resolve("clients");
        Files.createDirectories(clients);
        Path target = clients.resolve(client.release() + "-" + client.assemblyHash().substring(0, 16));
        if (!validCache(target, client, modulus)) {
            LOG.info("Preparing isolated Unity client {}", client.release());
            rebuild(client, target, modulus);
        }
        return new PreparedClient(
                client.release(),
                target,
                (RSAPrivateCrtKey) keyPair.getPrivate(),
                publicKey,
                cacheDirectory.resolve("client.log"));
    }

    private static ClientSource findClient() throws IOException {
        String roaming = System.getenv("APPDATA");
        if (roaming == null || roaming.isBlank()) {
            throw new IllegalStateException("APPDATA is unavailable");
        }
        Path base = Path.of(roaming, "Habbo Launcher", "downloads", "unity").toAbsolutePath().normalize();
        if (!Files.isDirectory(base)) {
            throw new IllegalStateException("No Unity standalone clients are installed");
        }

        ClientCandidate newest = null;
        try (var releases = Files.list(base)) {
            for (Path releaseDirectory : releases.filter(Files::isDirectory).toList()) {
                Path directory = releaseDirectory.resolve("StandaloneWindows").toAbsolutePath().normalize();
                Path assembly = directory.resolve("GameAssembly.dll");
                Path metadata = directory.resolve("habbo2020-global-prod_Data/il2cpp_data/Metadata/global-metadata.dat");
                Path executable = directory.resolve("habbo2020-global-prod.exe");
                if (!Files.isRegularFile(assembly) || !Files.isRegularFile(metadata) || !Files.isRegularFile(executable)) {
                    continue;
                }
                FileTime modified = Files.getLastModifiedTime(assembly);
                ClientCandidate candidate = new ClientCandidate(releaseDirectory.getFileName().toString(), directory, modified);
                if (newest == null || candidate.compareTo(newest) > 0) {
                    newest = candidate;
                }
            }
        }

        if (newest == null) {
            throw new IllegalStateException("No complete Unity standalone client is installed");
        }
        byte[] assembly = Files.readAllBytes(newest.directory().resolve("GameAssembly.dll"));
        String assemblyHash = hash(assembly);
        String metadataHash = hash(newest.directory().resolve("habbo2020-global-prod_Data/il2cpp_data/Metadata/global-metadata.dat"));
        int certificateVerifierOffset = findCertificateVerifier(assembly);
        LOG.info("Selected Unity standalone client {} modified at {}", newest.release(), newest.modified());
        return new ClientSource(
                newest.release(),
                newest.directory(),
                assemblyHash,
                metadataHash,
                certificateVerifierOffset);
    }

    private static KeyPair loadOrCreateKeys(Path directory) throws Exception {
        Files.createDirectories(directory);
        Path privatePath = directory.resolve("private.der");
        Path publicPath = directory.resolve("public.der");
        if (Files.isRegularFile(privatePath) && Files.isRegularFile(publicPath)) {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) factory.generatePrivate(
                    new PKCS8EncodedKeySpec(Files.readAllBytes(privatePath)));
            RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                    new X509EncodedKeySpec(Files.readAllBytes(publicPath)));
            if (privateKey.getModulus().equals(publicKey.getModulus())
                    && publicKey.getModulus().toString(16).length() == UnityStandaloneCrypto.SERVER_MODULUS.length()) {
                return new KeyPair(publicKey, privateKey);
            }
        }
        KeyPair keyPair = UnityStandaloneCrypto.newKeyPair();
        Files.write(privatePath, keyPair.getPrivate().getEncoded());
        Files.write(publicPath, keyPair.getPublic().getEncoded());
        return keyPair;
    }

    private static boolean validCache(Path target, ClientSource client, String modulus) {
        Path marker = target.resolve(".gearth-unity-client.properties");
        Path assembly = target.resolve("GameAssembly.dll");
        Path metadata = target.resolve("habbo2020-global-prod_Data/il2cpp_data/Metadata/global-metadata.dat");
        Path executable = target.resolve("habbo2020-global-prod.exe");
        if (!Files.isRegularFile(marker) || !Files.isRegularFile(assembly)
                || !Files.isRegularFile(metadata) || !Files.isRegularFile(executable)) {
            return false;
        }
        try (InputStream input = Files.newInputStream(marker)) {
            Properties values = new Properties();
            values.load(input);
            return client.release().equals(values.getProperty("release"))
                    && CACHE_FORMAT.equals(values.getProperty("format"))
                    && client.assemblyHash().equals(values.getProperty("sourceAssembly"))
                    && client.metadataHash().equals(values.getProperty("sourceMetadata"))
                    && Integer.toString(client.certificateVerifierOffset()).equals(values.getProperty("certificateVerifierOffset"))
                    && modulus.equals(values.getProperty("modulus"))
                    && hash(assembly).equals(values.getProperty("targetAssembly"))
                    && hash(metadata).equals(values.getProperty("targetMetadata"));
        } catch (Exception exception) {
            return false;
        }
    }

    private static void rebuild(ClientSource client, Path target, String modulus) throws Exception {
        Path clients = target.getParent().toAbsolutePath().normalize();
        Path staging = clients.resolve("." + target.getFileName() + "." + UUID.randomUUID() + ".tmp");
        try {
            copyTree(client.directory(), staging);
            patchMetadata(
                    staging.resolve("habbo2020-global-prod_Data/il2cpp_data/Metadata/global-metadata.dat"),
                    client.metadataHash(),
                    modulus);
            patchAssembly(
                    staging.resolve("GameAssembly.dll"),
                    client.assemblyHash(),
                    client.certificateVerifierOffset());
            Properties values = new Properties();
            values.setProperty("format", CACHE_FORMAT);
            values.setProperty("release", client.release());
            values.setProperty("sourceAssembly", client.assemblyHash());
            values.setProperty("sourceMetadata", client.metadataHash());
            values.setProperty("certificateVerifierOffset", Integer.toString(client.certificateVerifierOffset()));
            values.setProperty("modulus", modulus);
            values.setProperty("targetAssembly", hash(staging.resolve("GameAssembly.dll")));
            values.setProperty("targetMetadata", hash(staging.resolve("habbo2020-global-prod_Data/il2cpp_data/Metadata/global-metadata.dat")));
            try (var output = Files.newOutputStream(staging.resolve(".gearth-unity-client.properties"))) {
                values.store(output, null);
            }
            if (Files.exists(target)) {
                deleteTree(target, clients);
            }
            try {
                Files.move(staging, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException exception) {
                Files.move(staging, target);
            }
        } finally {
            if (Files.exists(staging)) {
                deleteTree(staging, clients);
            }
        }
    }

    private static void patchMetadata(Path path, String metadataHash, String modulus) throws IOException {
        byte[] source = Files.readAllBytes(path);
        if (!hash(source).equals(metadataHash)) {
            throw new IllegalStateException("Unexpected Unity metadata identity");
        }
        byte[] originalModulus = UnityStandaloneCrypto.SERVER_MODULUS.getBytes(StandardCharsets.US_ASCII);
        byte[] localModulus = modulus.getBytes(StandardCharsets.US_ASCII);
        if (localModulus.length != originalModulus.length || ORIGINAL_TEMPLATE.length != LOCAL_TEMPLATE.length) {
            throw new IllegalStateException("Unity metadata replacement width mismatch");
        }
        if (count(source, originalModulus) != 1 || count(source, localModulus) != 0
                || count(source, ORIGINAL_TEMPLATE) != 1 || count(source, LOCAL_TEMPLATE) != 0) {
            throw new IllegalStateException("Unexpected Unity metadata replacement inventory");
        }
        byte[] patched = source.clone();
        System.arraycopy(localModulus, 0, patched, indexOf(patched, originalModulus), localModulus.length);
        System.arraycopy(LOCAL_TEMPLATE, 0, patched, indexOf(patched, ORIGINAL_TEMPLATE), LOCAL_TEMPLATE.length);
        if (count(patched, originalModulus) != 0 || count(patched, localModulus) != 1
                || count(patched, ORIGINAL_TEMPLATE) != 0 || count(patched, LOCAL_TEMPLATE) != 1) {
            throw new IllegalStateException("Unity metadata replacement verification failed");
        }
        Files.write(path, patched);
    }

    private static void patchAssembly(Path path, String assemblyHash, int offset) throws IOException {
        byte[] source = Files.readAllBytes(path);
        if (!hash(source).equals(assemblyHash)) {
            throw new IllegalStateException("Unexpected Unity assembly identity");
        }
        if (offset < 0 || offset + CERTIFICATE_VERIFIER_BODY_OFFSET + CERTIFICATE_VERIFIER_BODY.length() > source.length
                || !Arrays.equals(
                Arrays.copyOfRange(source, offset, offset + CERTIFICATE_VERIFIER_PREFIX.length),
                CERTIFICATE_VERIFIER_PREFIX)
                || !CERTIFICATE_VERIFIER_BODY.matches(source, offset + CERTIFICATE_VERIFIER_BODY_OFFSET)) {
            throw new IllegalStateException("Unexpected Unity certificate verifier body");
        }
        byte[] patched = source.clone();
        System.arraycopy(ACCEPT_CERTIFICATE, 0, patched, offset, ACCEPT_CERTIFICATE.length);
        if (!Arrays.equals(
                Arrays.copyOfRange(patched, offset, offset + ACCEPT_CERTIFICATE.length),
                ACCEPT_CERTIFICATE)) {
            throw new IllegalStateException("Unity certificate verifier patch failed");
        }
        Files.write(path, patched);
    }

    private static int findCertificateVerifier(byte[] assembly) {
        int body = CERTIFICATE_VERIFIER_BODY.findUnique(assembly);
        int offset = body - CERTIFICATE_VERIFIER_BODY_OFFSET;
        if (offset < 0 || !Arrays.equals(
                Arrays.copyOfRange(assembly, offset, offset + CERTIFICATE_VERIFIER_PREFIX.length),
                CERTIFICATE_VERIFIER_PREFIX)) {
            throw new IllegalStateException("Unity certificate verifier could not be identified");
        }
        return offset;
    }

    private static void copyTree(Path source, Path target) throws IOException {
        Files.createDirectories(target);
        try (var paths = Files.walk(source)) {
            for (Path path : paths.sorted().toList()) {
                Path destination = target.resolve(source.relativize(path));
                if (Files.isDirectory(path)) {
                    Files.createDirectories(destination);
                } else {
                    Files.copy(path, destination, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
                }
            }
        }
    }

    private static void deleteTree(Path target, Path parent) throws IOException {
        Path normalized = target.toAbsolutePath().normalize();
        Path normalizedParent = parent.toAbsolutePath().normalize();
        if (normalized.equals(normalizedParent) || !normalized.startsWith(normalizedParent)) {
            throw new IOException("Refusing to delete a path outside the Unity client cache");
        }
        try (var paths = Files.walk(normalized)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static String hash(Path path) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = new DigestInputStream(Files.newInputStream(path), digest)) {
                input.transferTo(java.io.OutputStream.nullOutputStream());
            }
            return HEX.formatHex(digest.digest());
        } catch (java.security.GeneralSecurityException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static String hash(byte[] bytes) {
        try {
            return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (java.security.GeneralSecurityException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static int count(byte[] data, byte[] value) {
        int count = 0;
        int offset = 0;
        while ((offset = indexOf(data, value, offset)) >= 0) {
            count++;
            offset += value.length;
        }
        return count;
    }

    private static int indexOf(byte[] data, byte[] value) {
        return indexOf(data, value, 0);
    }

    private static int indexOf(byte[] data, byte[] value, int start) {
        int limit = data.length - value.length;
        for (int index = Math.max(0, start); index <= limit; index++) {
            int part = 0;
            while (part < value.length && data[index + part] == value[part]) {
                part++;
            }
            if (part == value.length) {
                return index;
            }
        }
        return -1;
    }

    record PreparedClient(
            String release,
            Path directory,
            RSAPrivateCrtKey privateKey,
            RSAPublicKey publicKey,
            Path log) {
    }

    private record ClientSource(
            String release,
            Path directory,
            String assemblyHash,
            String metadataHash,
            int certificateVerifierOffset) {
    }

    private record ClientCandidate(String release, Path directory, FileTime modified)
            implements Comparable<ClientCandidate> {

        @Override
        public int compareTo(ClientCandidate other) {
            int time = modified.compareTo(other.modified);
            return time != 0 ? time : release.compareTo(other.release);
        }
    }

    private record MaskedPattern(byte[] values, boolean[] fixed, int anchor) {

        static MaskedPattern compile(String pattern) {
            String[] parts = pattern.trim().split("\\s+");
            byte[] values = new byte[parts.length];
            boolean[] fixed = new boolean[parts.length];
            int anchor = -1;
            for (int index = 0; index < parts.length; index++) {
                if (!parts[index].equals("??")) {
                    values[index] = (byte) Integer.parseInt(parts[index], 16);
                    fixed[index] = true;
                    if (anchor < 0) {
                        anchor = index;
                    }
                }
            }
            if (anchor < 0) {
                throw new IllegalArgumentException("Binary pattern has no fixed bytes");
            }
            return new MaskedPattern(values, fixed, anchor);
        }

        int length() {
            return values.length;
        }

        boolean matches(byte[] source, int offset) {
            if (offset < 0 || offset + values.length > source.length) {
                return false;
            }
            for (int index = 0; index < values.length; index++) {
                if (fixed[index] && source[offset + index] != values[index]) {
                    return false;
                }
            }
            return true;
        }

        int findUnique(byte[] source) {
            int match = -1;
            int limit = source.length - values.length;
            for (int offset = 0; offset <= limit; offset++) {
                if (source[offset + anchor] != values[anchor] || !matches(source, offset)) {
                    continue;
                }
                if (match >= 0) {
                    throw new IllegalStateException("Unity certificate verifier is ambiguous");
                }
                match = offset;
            }
            if (match < 0) {
                throw new IllegalStateException("Unity certificate verifier was not found");
            }
            return match;
        }
    }
}
