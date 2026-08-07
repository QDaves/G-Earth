package gearth.app.protocol.connection.proxy.unity;

import gearth.app.protocol.HConnection;
import gearth.app.protocol.connection.HProxySetter;
import gearth.app.protocol.connection.HStateSetter;
import gearth.app.protocol.connection.proxy.ProxyProvider;
import gearth.app.protocol.connection.proxy.unity.standalone.UnityStandaloneProxyProvider;

import java.io.IOException;

public class UnityProxyProvider implements ProxyProvider {

    private final ProxyProvider provider;

    public UnityProxyProvider(HProxySetter proxySetter, HStateSetter stateSetter, HConnection hConnection) {
        this(proxySetter, stateSetter, hConnection, UnityLaunchMode.WEB);
    }

    public UnityProxyProvider(
            HProxySetter proxySetter,
            HStateSetter stateSetter,
            HConnection hConnection,
            UnityLaunchMode mode) {
        provider = switch (mode) {
            case WEB -> new UnityWebProxyProvider(proxySetter, stateSetter, hConnection);
            case STANDALONE -> new UnityStandaloneProxyProvider(proxySetter, stateSetter, hConnection);
        };
    }

    @Override
    public void start() throws IOException {
        provider.start();
    }

    @Override
    public void abort() {
        provider.abort();
    }
}
