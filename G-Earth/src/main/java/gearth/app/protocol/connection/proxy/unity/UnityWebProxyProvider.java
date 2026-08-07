package gearth.app.protocol.connection.proxy.unity;

import gearth.app.protocol.HConnection;
import gearth.app.protocol.StateChangeListener;
import gearth.app.protocol.connection.HProxySetter;
import gearth.app.protocol.connection.HState;
import gearth.app.protocol.connection.HStateSetter;
import gearth.app.protocol.connection.proxy.ProxyProvider;
import gearth.app.protocol.connection.proxy.http.HttpProxyManager;
import gearth.app.services.unity_tools.GUnityFileServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

final class UnityWebProxyProvider implements ProxyProvider, StateChangeListener {

    private static final Logger LOG = LoggerFactory.getLogger(UnityWebProxyProvider.class);

    private final HStateSetter stateSetter;
    private final HConnection hConnection;
    private final UnityWebsocketServer websocketServer;
    private final HttpProxyManager httpProxy;

    UnityWebProxyProvider(HProxySetter proxySetter, HStateSetter stateSetter, HConnection hConnection) {
        this.stateSetter = stateSetter;
        this.hConnection = hConnection;
        websocketServer = new UnityWebsocketServer(new UnityCommunicatorConfig(proxySetter, stateSetter, hConnection, this));
        httpProxy = new HttpProxyManager();
    }

    @Override
    public void start() throws IOException {
        try {
            hConnection.getStateObservable().addListener(this);
            LOG.info("Starting Unity WebSocket server");
            if (!websocketServer.start()) {
                LOG.error("Failed to start Unity WebSocket server");
                abort();
                return;
            }
            LOG.info("Unity WebSocket server started on port {}", websocketServer.getPort());
            LOG.info("Starting Unity HTTP proxy");
            if (!httpProxy.start(new GUnityFileServer(websocketServer.getPort()))) {
                LOG.error("Failed to start Unity HTTP proxy");
                abort();
                return;
            }
            LOG.info("Unity HTTP proxy started");
            stateSetter.setState(HState.WAITING_FOR_CLIENT);
        } catch (Exception exception) {
            LOG.error("Failed to start Unity web proxy", exception);
            abort();
        }
    }

    @Override
    public synchronized void abort() {
        stateSetter.setState(HState.ABORTING);
        Thread thread = new Thread(() -> {
            hConnection.getStateObservable().removeListener(this);
            try {
                websocketServer.stop();
            } catch (Exception exception) {
                LOG.error("Failed to stop Unity WebSocket server", exception);
            }
            try {
                httpProxy.stop();
            } catch (Exception exception) {
                LOG.error("Failed to stop Unity HTTP proxy", exception);
            }
            stateSetter.setState(HState.NOT_CONNECTED);
        }, "unity-web-proxy-stop");
        thread.setDaemon(true);
        thread.start();
    }

    @Override
    public void stateChanged(HState oldState, HState newState) {
        if (oldState == HState.WAITING_FOR_CLIENT && newState == HState.CONNECTED) {
            httpProxy.pause();
            LOG.info("Unity web proxy paused");
        }
    }
}
