package gearth.app.protocol.connection.proxy.unity.standalone;

import gearth.app.misc.Cacher;
import gearth.app.misc.OSValidator;
import gearth.app.protocol.HConnection;
import gearth.app.protocol.connection.HProxySetter;
import gearth.app.protocol.connection.HState;
import gearth.app.protocol.connection.HStateSetter;
import gearth.app.protocol.connection.proxy.ProxyProvider;
import gearth.app.protocol.connection.proxy.unity.UnityCommunicatorConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;

public final class UnityStandaloneProxyProvider implements ProxyProvider {

    private static final Logger LOG = LoggerFactory.getLogger(UnityStandaloneProxyProvider.class);
    private static final int DEFAULT_PORT = 30001;

    private final HStateSetter stateSetter;
    private final UnityCommunicatorConfig config;
    private final AtomicBoolean stopping = new AtomicBoolean();
    private volatile UnityStandaloneGateway gateway;

    public UnityStandaloneProxyProvider(HProxySetter proxySetter, HStateSetter stateSetter, HConnection hConnection) {
        this.stateSetter = stateSetter;
        config = new UnityCommunicatorConfig(proxySetter, stateSetter, hConnection, this);
    }

    @Override
    public synchronized void start() throws IOException {
        try {
            if (!OSValidator.isWindows()) {
                throw new IOException("Unity standalone is only available on Windows");
            }
            stateSetter.setState(HState.PREPARING);
            Path cache = Cacher.getCacheDir().toPath().resolve("unity-standalone");
            UnityStandaloneClient.PreparedClient client = new UnityStandaloneClient(cache).prepare();
            int port = Integer.getInteger("gearth.unity.port", DEFAULT_PORT);
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Invalid Unity standalone endpoint");
            }
            UnityStandaloneGateway next = new UnityStandaloneGateway(config, client, port, cache.resolve("certificates"));
            gateway = next;
            stateSetter.setState(HState.WAITING_FOR_CLIENT);
            next.start();
        } catch (Exception exception) {
            LOG.error("Failed to start Unity standalone proxy", exception);
            abort();
        }
    }

    @Override
    public void abort() {
        if (!stopping.compareAndSet(false, true)) {
            return;
        }
        stateSetter.setState(HState.ABORTING);
        Thread thread = new Thread(() -> {
            UnityStandaloneGateway current = gateway;
            gateway = null;
            if (current != null) {
                current.close();
            }
            config.proxySetter().setProxy(null);
            stateSetter.setState(HState.NOT_CONNECTED);
            stopping.set(false);
        }, "unity-standalone-proxy-stop");
        thread.setDaemon(true);
        thread.start();
    }
}
