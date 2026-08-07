package gearth.app.protocol.connection.proxy.unity.standalone;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

final class UnityInnerTlsEndpoint {

    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);
    private static final int MAXIMUM_PENDING_BYTES = 0x800000;

    private final SSLEngine engine;
    private final ArrayDeque<ByteBuffer> applicationQueue = new ArrayDeque<>();
    private ByteBuffer networkInput;
    private boolean started;
    private boolean secure;

    private UnityInnerTlsEndpoint(SSLEngine engine) {
        this.engine = engine;
        networkInput = ByteBuffer.allocate(engine.getSession().getPacketBufferSize() * 2);
    }

    static UnityInnerTlsEndpoint client(SSLContext context, String host, int port) {
        SSLEngine engine = context.createSSLEngine(host, port);
        engine.setUseClientMode(true);
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setServerNames(List.of(new SNIHostName(host)));
        engine.setSSLParameters(parameters);
        return new UnityInnerTlsEndpoint(engine);
    }

    static UnityInnerTlsEndpoint server(SSLContext context) {
        SSLEngine engine = context.createSSLEngine();
        engine.setUseClientMode(false);
        return new UnityInnerTlsEndpoint(engine);
    }

    Update start() throws SSLException {
        if (started) {
            throw new IllegalStateException("TLS endpoint is already started");
        }
        started = true;
        engine.beginHandshake();
        return advance();
    }

    Update receive(byte[] bytes) throws SSLException {
        if (!started) {
            throw new IllegalStateException("TLS endpoint is not started");
        }
        append(bytes);
        return advance();
    }

    Update send(byte[] bytes) throws SSLException {
        if (!started) {
            throw new IllegalStateException("TLS endpoint is not started");
        }
        if (bytes.length != 0) {
            applicationQueue.add(ByteBuffer.wrap(bytes));
        }
        return advance();
    }

    boolean secure() {
        return secure;
    }

    private Update advance() throws SSLException {
        List<byte[]> network = new ArrayList<>();
        List<byte[]> application = new ArrayList<>();
        for (int iteration = 0; iteration < 10000; iteration++) {
            SSLEngineResult.HandshakeStatus status = engine.getHandshakeStatus();
            if (status == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                Runnable task;
                while ((task = engine.getDelegatedTask()) != null) {
                    task.run();
                }
                continue;
            }
            if (status == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                wrap(false, network);
                continue;
            }
            if (status == SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN) {
                unwrap(true, application);
                continue;
            }
            if (status == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                if (networkInput.position() == 0 || !unwrap(false, application)) {
                    break;
                }
                continue;
            }
            secure = true;
            if (networkInput.position() != 0) {
                if (!unwrap(false, application)) {
                    break;
                }
                continue;
            }
            if (!applicationQueue.isEmpty()) {
                wrap(true, network);
                continue;
            }
            return new Update(List.copyOf(network), List.copyOf(application));
        }
        return new Update(List.copyOf(network), List.copyOf(application));
    }

    private void wrap(boolean application, List<byte[]> output) throws SSLException {
        ByteBuffer source = application && !applicationQueue.isEmpty() ? applicationQueue.peek() : EMPTY;
        ByteBuffer destination = ByteBuffer.allocate(engine.getSession().getPacketBufferSize() * 2);
        SSLEngineResult result = engine.wrap(source, destination);
        verify(result, "wrap");
        if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
            throw new SSLException("TLS packet buffer overflow");
        }
        if (application && source != EMPTY && !source.hasRemaining()) {
            applicationQueue.remove();
        }
        if (destination.position() != 0) {
            output.add(copy(destination));
        }
        update(result);
    }

    private boolean unwrap(boolean again, List<byte[]> output) throws SSLException {
        ByteBuffer source;
        if (again) {
            source = EMPTY;
        } else {
            networkInput.flip();
            source = networkInput;
        }
        ByteBuffer destination = ByteBuffer.allocate(engine.getSession().getApplicationBufferSize() * 2);
        SSLEngineResult result;
        try {
            result = engine.unwrap(source, destination);
        } finally {
            if (!again) {
                networkInput.compact();
            }
        }
        verify(result, "unwrap");
        if (result.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
            throw new SSLException("TLS application buffer overflow");
        }
        if (destination.position() != 0) {
            output.add(copy(destination));
        }
        update(result);
        return result.getStatus() != SSLEngineResult.Status.BUFFER_UNDERFLOW;
    }

    private void append(byte[] bytes) throws SSLException {
        if (bytes.length == 0) {
            return;
        }
        if ((long) networkInput.position() + bytes.length > MAXIMUM_PENDING_BYTES) {
            throw new SSLException("TLS input exceeds the pending limit");
        }
        if (networkInput.remaining() < bytes.length) {
            int required = networkInput.position() + bytes.length;
            int capacity = networkInput.capacity();
            while (capacity < required) {
                capacity = Math.multiplyExact(capacity, 2);
            }
            ByteBuffer replacement = ByteBuffer.allocate(capacity);
            networkInput.flip();
            replacement.put(networkInput);
            networkInput = replacement;
        }
        networkInput.put(bytes);
    }

    private void update(SSLEngineResult result) {
        if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED) {
            secure = true;
        }
    }

    private static void verify(SSLEngineResult result, String operation) throws SSLException {
        if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
            throw new SSLException("TLS endpoint closed during " + operation);
        }
    }

    private static byte[] copy(ByteBuffer buffer) {
        buffer.flip();
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        return bytes;
    }

    record Update(List<byte[]> network, List<byte[]> application) {
    }
}
