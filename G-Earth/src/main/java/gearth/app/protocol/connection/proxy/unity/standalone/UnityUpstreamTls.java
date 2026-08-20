package gearth.app.protocol.connection.proxy.unity.standalone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

final class UnityUpstreamTls implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(UnityUpstreamTls.class);
    private static final String EXECUTABLE = "unity-tls-relay-x86.exe";
    private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

    private final Process process;
    private final BufferedReader output;
    private final int port;

    private UnityUpstreamTls(Process process, BufferedReader output, int port) {
        this.process = process;
        this.output = output;
        this.port = port;
    }

    static UnityUpstreamTls connect(String host, int port) throws IOException {
        Path executable = executable();
        Process process = new ProcessBuilder(
                executable.toString(),
                host,
                Integer.toString(port),
                Long.toString(ProcessHandle.current().pid()))
                .redirectErrorStream(true)
                .start();
        BufferedReader output = new BufferedReader(new InputStreamReader(
                process.getInputStream(),
                StandardCharsets.UTF_8));

        try {
            int localPort = awaitPort(process, output);
            UnityUpstreamTls relay = new UnityUpstreamTls(process, output, localPort);
            relay.drainOutput();
            return relay;
        } catch (IOException exception) {
            stop(process);
            throw exception;
        }
    }

    int port() {
        return port;
    }

    @Override
    public void close() {
        stop(process);
        try {
            output.close();
        } catch (IOException ignored) {
        }
    }

    private void drainOutput() {
        Thread thread = new Thread(() -> {
            try {
                String line;
                while ((line = output.readLine()) != null) {
                    LOG.warn("Unity upstream TLS relay: {}", line);
                }
            } catch (IOException exception) {
                if (process.isAlive()) {
                    LOG.warn("Unity upstream TLS relay output failed", exception);
                }
            }
        }, "unity-upstream-tls");
        thread.setDaemon(true);
        thread.start();
    }

    private static int awaitPort(Process process, BufferedReader output) throws IOException {
        long deadline = System.nanoTime() + START_TIMEOUT.toNanos();
        while (System.nanoTime() < deadline) {
            if (output.ready()) {
                String line = output.readLine();
                if (line != null && line.startsWith("READY ")) {
                    try {
                        int port = Integer.parseInt(line.substring(6));
                        if (port > 0 && port <= 65535) {
                            return port;
                        }
                    } catch (NumberFormatException ignored) {
                    }
                }
                throw new IOException("Unity upstream TLS relay failed: " + line);
            }
            if (!process.isAlive()) {
                String line = output.readLine();
                throw new IOException("Unity upstream TLS relay exited before startup: " + line);
            }
            try {
                Thread.sleep(10);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new IOException("Unity upstream TLS relay startup was interrupted", exception);
            }
        }
        throw new IOException("Unity upstream TLS relay did not start within " + START_TIMEOUT.toSeconds() + " seconds");
    }

    private static Path executable() throws IOException {
        Path location;
        try {
            location = Path.of(UnityUpstreamTls.class
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI());
        } catch (URISyntaxException exception) {
            throw new IOException("Unity upstream TLS relay location is invalid", exception);
        }

        Path directory = Files.isDirectory(location) ? location : location.getParent();
        if (directory == null) {
            throw new IOException("Unity upstream TLS relay directory is unavailable");
        }
        Path parent = directory.getParent();
        Path working = Path.of("").toAbsolutePath();
        List<Path> candidates = List.of(
                directory.resolve(EXECUTABLE),
                directory.resolve("build").resolve("windows").resolve(EXECUTABLE),
                parent == null ? directory.resolve(EXECUTABLE) : parent.resolve(EXECUTABLE),
                working.resolve("src").resolve("main").resolve("resources").resolve("build").resolve("windows").resolve(EXECUTABLE),
                working.resolve("G-Earth").resolve("src").resolve("main").resolve("resources").resolve("build").resolve("windows").resolve(EXECUTABLE));
        for (Path candidate : candidates) {
            if (Files.isRegularFile(candidate)) {
                return candidate.toAbsolutePath();
            }
        }
        throw new IOException("Unity upstream TLS relay is missing: " + EXECUTABLE);
    }

    private static void stop(Process process) {
        if (!process.isAlive()) {
            return;
        }
        process.destroy();
        try {
            if (!process.waitFor(2, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                process.waitFor(2, TimeUnit.SECONDS);
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
        }
    }
}
