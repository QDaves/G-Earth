package gearth.app.protocol.connection.proxy.unity.standalone;

import gearth.app.protocol.HConnection;
import gearth.app.protocol.connection.HProxy;
import gearth.app.protocol.connection.HState;
import gearth.app.protocol.connection.proxy.http.WebSession;
import gearth.app.protocol.connection.proxy.unity.UnityCommunicatorConfig;
import gearth.app.protocol.packethandler.unity.UnityPacketHandler;
import gearth.app.services.packet_info.PacketInfoManagerRemote;
import gearth.protocol.HMessage;
import gearth.protocol.connection.HClient;
import gearth.services.packet_info.PacketInfoManager;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler;
import io.netty.handler.codec.http.websocketx.WebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketFrameAggregator;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;
import io.netty.handler.codec.http.websocketx.WebSocketVersion;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.ReferenceCountUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIHostName;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

final class UnityStandaloneGateway implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger(UnityStandaloneGateway.class);
    private static final byte[] START_TLS = "StartTLS".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] TLS_READY = "OK".getBytes(StandardCharsets.US_ASCII);
    private static final String LOCAL_HOST = "127.0.0.1";
    private static final int MAXIMUM_FRAME_LENGTH = 0x200000;
    private static final int MAXIMUM_PENDING_LENGTH = 0x800000;
    private static final Duration INTERCEPT_TIMEOUT = Duration.ofSeconds(5);

    private final UnityCommunicatorConfig config;
    private final UnityStandaloneClient.PreparedClient client;
    private final int port;
    private final Path certificateDirectory;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean failed = new AtomicBoolean();
    private final AtomicReference<Channel> localConnection = new AtomicReference<>();
    private final ExecutorService protocolExecutor;

    private volatile MultiThreadIoEventLoopGroup networkGroup;
    private volatile Channel upstream;
    private volatile Channel localServer;
    private volatile Bridge bridge;
    private volatile Process clientProcess;
    private volatile String upstreamHost;

    UnityStandaloneGateway(
            UnityCommunicatorConfig config,
            UnityStandaloneClient.PreparedClient client,
            int port,
            Path certificateDirectory) {
        this.config = config;
        this.client = client;
        this.port = port;
        this.certificateDirectory = certificateDirectory;
        protocolExecutor = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "unity-standalone-protocol");
            thread.setDaemon(true);
            return thread;
        });
    }

    void start() throws Exception {
        PacketInfoManager packetInfoManager = PacketInfoManagerRemote.fromHotelVersion(client.release(), HClient.UNITY);
        UnityHandshakeHeaders headers = UnityHandshakeHeaders.from(packetInfoManager);
        UnityHandshakeTranslator translator = new UnityHandshakeTranslator(headers, client.privateKey(), client.publicKey());
        SSLContext serverContext = new UnityLocalCertificate(certificateDirectory).serverContext(LOCAL_HOST);
        SSLContext clientContext = SSLContext.getInstance("TLS");
        clientContext.init(null, new javax.net.ssl.TrustManager[]{new UnityInnerTlsTrust()}, null);
        bridge = new Bridge(serverContext, clientContext, translator);
        startLocalServer(serverContext);
        Path executable = client.directory().resolve("habbo2020-global-prod.exe").toAbsolutePath();
        if (!Files.isRegularFile(executable)) {
            throw new IOException("Unity client executable is missing: " + executable);
        }
        ProcessBuilder builder = new ProcessBuilder(executable.toString())
                .directory(client.directory().toFile())
                .redirectErrorStream(true)
                .redirectOutput(client.log().toFile());
        clientProcess = builder.start();
        LOG.info("Unity standalone client {} started with process id {}", client.release(), clientProcess.pid());
        Process launched = clientProcess;
        launched.onExit().thenRun(() -> {
            if (!closed.get()) {
                LOG.info("Unity standalone client exited with code {}", launched.exitValue());
                config.proxyProvider().abort();
            }
        });
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        Channel server = localServer;
        if (server != null) {
            server.close().syncUninterruptibly();
        }
        Channel local = localConnection.getAndSet(null);
        if (local != null) {
            local.close().syncUninterruptibly();
        }
        Channel remote = upstream;
        if (remote != null) {
            remote.close().syncUninterruptibly();
        }
        MultiThreadIoEventLoopGroup group = networkGroup;
        if (group != null) {
            group.shutdownGracefully().syncUninterruptibly();
        }
        Process process = clientProcess;
        if (process != null && process.isAlive()) {
            process.destroy();
            try {
                if (!process.waitFor(5, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                process.destroyForcibly();
            }
        }
        protocolExecutor.shutdownNow();
    }

    private void submit(Runnable task) {
        if (closed.get()) {
            return;
        }
        try {
            protocolExecutor.execute(() -> {
                try {
                    task.run();
                } catch (RuntimeException exception) {
                    fail(exception);
                }
            });
        } catch (RejectedExecutionException exception) {
            if (!closed.get()) {
                fail(exception);
            }
        }
    }

    private void fail(Throwable cause) {
        if (closed.get() || !failed.compareAndSet(false, true)) {
            return;
        }
        LOG.error("Unity standalone connection failed", cause);
        config.proxyProvider().abort();
    }

    private void connectUpstream() throws Exception {
        if (upstream != null) {
            return;
        }
        String host = upstreamHost;
        if (host == null) {
            throw new IllegalStateException("Unity client did not select an upstream host");
        }
        URI uri = URI.create("wss://" + host + ":" + port + "/websocket");
        CompletableFuture<Void> handshake = new CompletableFuture<>();
        Channel remote = new Bootstrap()
                .group(networkGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10000)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel channel) throws Exception {
                        channel.pipeline().addLast("ssl", upstreamSsl(host));
                        channel.pipeline().addLast("http", new HttpClientCodec());
                        channel.pipeline().addLast("httpAggregator", new HttpObjectAggregator(65536));
                        channel.pipeline().addLast("websocket", new WebSocketClientProtocolHandler(
                                uri,
                                WebSocketVersion.V13,
                                null,
                                false,
                                new DefaultHttpHeaders(),
                                MAXIMUM_FRAME_LENGTH));
                        channel.pipeline().addLast("websocketAggregator", new WebSocketFrameAggregator(MAXIMUM_FRAME_LENGTH));
                        channel.pipeline().addLast("frames", new UpstreamFrames(handshake));
                    }
                })
                .connect(host, port)
                .sync()
                .channel();
        upstream = remote;
        try {
            handshake.get(15, TimeUnit.SECONDS);
        } catch (Exception exception) {
            upstream = null;
            remote.close();
            if (exception instanceof ExecutionException execution && execution.getCause() instanceof Exception cause) {
                throw cause;
            }
            throw new IOException("Unity upstream WebSocket connection failed", exception);
        }
    }

    private void startLocalServer(SSLContext serverContext) throws Exception {
        networkGroup = new MultiThreadIoEventLoopGroup(2, NioIoHandler.newFactory());
        localServer = new ServerBootstrap()
                .group(networkGroup)
                .channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, 16)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel channel) {
                        channel.pipeline().addLast("ssl", localSsl(serverContext));
                        channel.pipeline().addLast("http", new HttpServerCodec());
                        channel.pipeline().addLast("httpAggregator", new HttpObjectAggregator(65536));
                        channel.pipeline().addLast("endpoint", new LocalEndpoint());
                        channel.pipeline().addLast("websocket", new WebSocketServerProtocolHandler(
                                "/", null, false, MAXIMUM_FRAME_LENGTH, false, true));
                        channel.pipeline().addLast("websocketAggregator", new WebSocketFrameAggregator(MAXIMUM_FRAME_LENGTH));
                        channel.pipeline().addLast("frames", new LocalFrames());
                    }
                })
                .bind(new InetSocketAddress(LOCAL_HOST, port))
                .sync()
                .channel();
        LOG.info("Unity local WebSocket gateway listening on {}:{}", LOCAL_HOST, port);
    }

    private SslHandler localSsl(SSLContext context) {
        SSLEngine engine = context.createSSLEngine(LOCAL_HOST, port);
        engine.setUseClientMode(false);
        SslHandler handler = new SslHandler(engine);
        handler.setHandshakeTimeout(10, TimeUnit.SECONDS);
        return handler;
    }

    private SslHandler upstreamSsl(String host) throws Exception {
        SSLEngine engine = SSLContext.getDefault().createSSLEngine(host, port);
        engine.setUseClientMode(true);
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setServerNames(List.of(new SNIHostName(host)));
        engine.setSSLParameters(parameters);
        SslHandler handler = new SslHandler(engine);
        handler.setHandshakeTimeout(10, TimeUnit.SECONDS);
        return handler;
    }

    private void selectUpstream(String resource) {
        if (resource == null || resource.length() < 2 || resource.charAt(0) != '/') {
            throw new IllegalArgumentException("Unity client did not provide an upstream host");
        }
        String host = resource.substring(1).toLowerCase(Locale.ROOT);
        if (!host.matches("game-[a-z0-9-]+\\.habbo\\.com")) {
            throw new IllegalArgumentException("Unity client selected an invalid upstream host");
        }
        if (upstreamHost != null && !upstreamHost.equals(host)) {
            throw new IllegalStateException("Unity upstream host is already selected");
        }
        upstreamHost = host;
        bridge.selectUpstream(host);
    }

    private final class Bridge {
        private final UnityInnerTlsEndpoint localTls;
        private final SSLContext clientContext;
        private final UnityHandshakeTranslator translator;
        private final ProtocolStream clientStream = new ProtocolStream(false);
        private final ProtocolStream serverStream = new ProtocolStream(true);
        private final GatewaySession session = new GatewaySession();
        private boolean startRequested;
        private boolean tlsStarted;
        private boolean tlsReported;
        private boolean cipherReported;
        private HProxy proxy;
        private UnityInnerTlsEndpoint upstreamTls;

        private Bridge(SSLContext serverContext, SSLContext clientContext, UnityHandshakeTranslator translator) {
            localTls = UnityInnerTlsEndpoint.server(serverContext);
            this.clientContext = clientContext;
            this.translator = translator;
        }

        private void selectUpstream(String host) {
            if (upstreamTls != null) {
                throw new IllegalStateException("Unity upstream TLS endpoint is already selected");
            }
            upstreamTls = UnityInnerTlsEndpoint.client(clientContext, host, port);
        }

        private void fromClient(byte[] bytes) {
            try {
                if (!startRequested) {
                    if (!Arrays.equals(bytes, START_TLS)) {
                        throw new IllegalArgumentException("Expected StartTLS from the Unity client");
                    }
                    if (upstreamTls == null) {
                        throw new IllegalStateException("Unity client started TLS before selecting an upstream host");
                    }
                    startRequested = true;
                    connectUpstream();
                    sendUpstream(bytes);
                    return;
                }
                if (!tlsStarted) {
                    throw new IllegalStateException("Unity client sent TLS data before the upstream acknowledgement");
                }
                routeLocal(localTls.receive(bytes));
            } catch (Exception exception) {
                throw new IllegalStateException("Unity client TLS failed", exception);
            }
        }

        private void fromServer(byte[] bytes) {
            try {
                if (!startRequested) {
                    throw new IllegalStateException("Unity upstream sent data before StartTLS");
                }
                if (!tlsStarted) {
                    if (!Arrays.equals(bytes, TLS_READY)) {
                        throw new IllegalStateException("Unexpected Unity upstream TLS acknowledgement");
                    }
                    sendLocal(bytes);
                    tlsStarted = true;
                    routeLocal(localTls.start());
                    routeUpstream(upstreamTls.start());
                    return;
                }
                routeUpstream(upstreamTls.receive(bytes));
            } catch (Exception exception) {
                throw new IllegalStateException("Unity upstream TLS failed", exception);
            }
        }

        private void routeLocal(UnityInnerTlsEndpoint.Update update) throws Exception {
            for (byte[] network : update.network()) {
                sendLocal(network);
            }
            for (byte[] plain : update.application()) {
                byte[] translated = clientStream.accept(plain, this::fromClientFrame);
                if (translated != null) {
                    routeUpstream(upstreamTls.send(translated));
                }
            }
            reportTls();
        }

        private void routeUpstream(UnityInnerTlsEndpoint.Update update) throws Exception {
            for (byte[] network : update.network()) {
                sendUpstream(network);
            }
            for (byte[] plain : update.application()) {
                byte[] translated = serverStream.accept(plain, this::fromServerFrame);
                if (translated != null) {
                    routeLocal(localTls.send(translated));
                }
            }
            reportTls();
        }

        private void reportTls() {
            if (!tlsReported && localTls.secure() && upstreamTls.secure()) {
                tlsReported = true;
                LOG.info("Unity inner TLS established");
            }
        }

        private byte[] fromClientFrame(byte[] frame) {
            UnityHandshakeTranslator.DecodedPacket decoded = translator.receiveClient(frame);
            if (proxy == null && translator.isClientHello(decoded.header())) {
                connectProxy(decoded.source());
            }
            if (proxy == null) {
                throw new IllegalStateException("Unity packet stream began before the client hello");
            }
            if (decoded.handshake()) {
                ((UnityPacketHandler) proxy.getOutHandler()).report(decoded.source());
                return translator.sendToServer(decoded.destination(), false);
            }
            UnityPacketHandler.Verdict verdict = intercept(proxy.getOutHandler(), decoded.source());
            return verdict.blocked() ? null : translator.sendToServer(verdict.bytes(), true);
        }

        private byte[] fromServerFrame(byte[] frame) {
            UnityHandshakeTranslator.DecodedPacket decoded = translator.receiveServer(frame);
            if (!cipherReported && translator.active()) {
                cipherReported = true;
                LOG.info("Unity protocol encryption established");
            }
            if (proxy == null) {
                throw new IllegalStateException("Unity server packet arrived before the client hello");
            }
            if (decoded.handshake()) {
                ((UnityPacketHandler) proxy.getInHandler()).report(decoded.destination());
                return translator.sendToClient(decoded.destination(), false);
            }
            UnityPacketHandler.Verdict verdict = intercept(proxy.getInHandler(), decoded.source());
            return verdict.blocked() ? null : translator.sendToClient(verdict.bytes(), true);
        }

        private UnityPacketHandler.Verdict intercept(gearth.app.protocol.packethandler.PacketHandler handler, byte[] packet) {
            try {
                return ((UnityPacketHandler) handler).intercept(packet, INTERCEPT_TIMEOUT);
            } catch (IOException exception) {
                throw new IllegalStateException("Unity packet interception failed", exception);
            }
        }

        private void connectProxy(byte[] hello) {
            String clientIdentifier = UnityHandshakeTranslator.clientIdentifier(hello);
            HConnection connection = config.hConnection();
            proxy = new HProxy(HClient.UNITY, upstreamHost, upstreamHost, port, port, LOCAL_HOST);
            proxy.verifyProxy(
                    new UnityPacketHandler(connection.getExtensionHandler(), connection.getTrafficObservables(), session, HMessage.Direction.TOCLIENT),
                    new UnityPacketHandler(connection.getExtensionHandler(), connection.getTrafficObservables(), session, HMessage.Direction.TOSERVER),
                    clientIdentifier,
                    clientIdentifier);
            config.proxySetter().setProxy(proxy);
            config.stateSetter().setState(HState.CONNECTED);
            LOG.info("Unity standalone packet stream connected as {}", clientIdentifier);
        }

        private void inject(byte[] buffer) {
            if (buffer.length < 7 || !translator.active() || !localTls.secure() || !upstreamTls.secure()) {
                return;
            }
            byte direction = buffer[0];
            byte[] packet = Arrays.copyOfRange(buffer, 1, buffer.length);
            UnityHandshakeTranslator.validateFrame(packet);
            try {
                if (direction == 0) {
                    routeLocal(localTls.send(translator.sendToClient(packet, true)));
                } else if (direction == 1) {
                    routeUpstream(upstreamTls.send(translator.sendToServer(packet, true)));
                } else {
                    throw new IllegalArgumentException("Unknown Unity packet direction: " + direction);
                }
            } catch (Exception exception) {
                throw new IllegalStateException("Unity packet injection failed", exception);
            }
        }

        private final class GatewaySession implements WebSession {
            @Override
            public boolean send(byte[] buffer) {
                if (closed.get()) {
                    return false;
                }
                byte[] copy = buffer.clone();
                submit(() -> inject(copy));
                return true;
            }
        }
    }

    private final class LocalEndpoint extends SimpleChannelInboundHandler<FullHttpRequest> {
        private LocalEndpoint() {
            super(false);
        }

        @Override
        protected void channelRead0(ChannelHandlerContext context, FullHttpRequest request) {
            try {
                selectUpstream(request.uri());
                context.pipeline().remove(this);
                context.fireChannelRead(request);
            } catch (RuntimeException exception) {
                ReferenceCountUtil.release(request);
                context.close();
                fail(exception);
            }
        }
    }

    private final class LocalFrames extends SimpleChannelInboundHandler<WebSocketFrame> {
        @Override
        public void userEventTriggered(ChannelHandlerContext context, Object event) {
            if (event == WebSocketServerProtocolHandler.ServerHandshakeStateEvent.HANDSHAKE_COMPLETE) {
                if (!localConnection.compareAndSet(null, context.channel())) {
                    context.writeAndFlush(new CloseWebSocketFrame(1013, "A Unity client is already connected"));
                    context.close();
                    return;
                }
                LOG.info("Unity standalone client connected to the local gateway");
            }
            context.fireUserEventTriggered(event);
        }

        @Override
        protected void channelRead0(ChannelHandlerContext context, WebSocketFrame frame) {
            if (frame instanceof BinaryWebSocketFrame binary) {
                byte[] bytes = new byte[binary.content().readableBytes()];
                binary.content().getBytes(binary.content().readerIndex(), bytes);
                submit(() -> bridge.fromClient(bytes));
            } else if (frame instanceof TextWebSocketFrame) {
                fail(new IOException("Unity client sent a text WebSocket frame"));
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext context) {
            if (localConnection.compareAndSet(context.channel(), null) && !closed.get()) {
                LOG.info("Unity standalone client WebSocket closed");
                config.proxyProvider().abort();
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
            context.close();
            fail(cause);
        }
    }

    private final class UpstreamFrames extends SimpleChannelInboundHandler<WebSocketFrame> {
        private final CompletableFuture<Void> handshake;

        private UpstreamFrames(CompletableFuture<Void> handshake) {
            this.handshake = handshake;
        }

        @Override
        public void userEventTriggered(ChannelHandlerContext context, Object event) {
            if (event == WebSocketClientProtocolHandler.ClientHandshakeStateEvent.HANDSHAKE_COMPLETE) {
                LOG.info("Unity upstream WebSocket connected to {}", upstreamHost);
                handshake.complete(null);
            }
            context.fireUserEventTriggered(event);
        }

        @Override
        protected void channelRead0(ChannelHandlerContext context, WebSocketFrame frame) {
            if (frame instanceof BinaryWebSocketFrame binary) {
                byte[] bytes = new byte[binary.content().readableBytes()];
                binary.content().getBytes(binary.content().readerIndex(), bytes);
                submit(() -> bridge.fromServer(bytes));
            } else if (frame instanceof TextWebSocketFrame) {
                fail(new IOException("Unity upstream sent a text WebSocket frame"));
            }
        }

        @Override
        public void channelInactive(ChannelHandlerContext context) {
            handshake.completeExceptionally(new IOException("Unity upstream WebSocket closed during handshake"));
            if (!closed.get()) {
                LOG.info("Unity upstream WebSocket closed");
                config.proxyProvider().abort();
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
            handshake.completeExceptionally(cause);
            context.close();
            fail(cause);
        }
    }

    private static final class ProtocolStream {
        private final boolean serverSide;
        private final ByteArrayOutputStream pending = new ByteArrayOutputStream();
        private boolean framed;

        private ProtocolStream(boolean serverSide) {
            this.serverSide = serverSide;
        }

        private byte[] accept(byte[] chunk, Function<byte[], byte[]> transform) {
            if (!framed && Arrays.equals(chunk, START_TLS)) {
                return chunk;
            }
            if (!framed && !looksLikeFrame(chunk)) {
                if (serverSide) {
                    return chunk;
                }
                throw new IllegalArgumentException("Unexpected Unity client payload before the packet stream");
            }
            framed = true;
            if ((long) pending.size() + chunk.length > MAXIMUM_PENDING_LENGTH) {
                throw new IllegalArgumentException("Unity packet stream exceeds the pending limit");
            }
            pending.writeBytes(chunk);
            byte[] source = pending.toByteArray();
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            int offset = 0;
            while (source.length - offset >= 4) {
                int declared = ByteBuffer.wrap(source, offset, 4).getInt();
                if (declared < 2 || declared > MAXIMUM_FRAME_LENGTH) {
                    throw new IllegalArgumentException("Invalid Unity packet length: " + declared);
                }
                int total = declared + 4;
                if (source.length - offset < total) {
                    break;
                }
                byte[] frame = Arrays.copyOfRange(source, offset, offset + total);
                byte[] translated = transform.apply(frame);
                if (translated != null) {
                    UnityHandshakeTranslator.validateFrame(translated);
                    output.writeBytes(translated);
                }
                offset += total;
            }
            pending.reset();
            if (offset < source.length) {
                pending.write(source, offset, source.length - offset);
            }
            return output.size() == 0 ? null : output.toByteArray();
        }

        private static boolean looksLikeFrame(byte[] bytes) {
            if (bytes.length < 4) {
                return false;
            }
            int declared = ByteBuffer.wrap(bytes, 0, 4).getInt();
            return declared >= 2 && declared <= MAXIMUM_FRAME_LENGTH;
        }
    }

    private void sendLocal(byte[] bytes) {
        Channel socket = localConnection.get();
        if (socket == null || !socket.isActive()) {
            throw new IllegalStateException("Unity local WebSocket is not connected");
        }
        socket.writeAndFlush(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(bytes)));
    }

    private void sendUpstream(byte[] bytes) {
        Channel remote = upstream;
        if (remote == null || !remote.isActive()) {
            throw new IllegalStateException("Unity upstream WebSocket is not connected");
        }
        remote.writeAndFlush(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(bytes)));
    }
}
