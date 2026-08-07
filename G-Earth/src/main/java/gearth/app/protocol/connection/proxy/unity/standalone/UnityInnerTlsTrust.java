package gearth.app.protocol.connection.proxy.unity.standalone;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

final class UnityInnerTlsTrust extends X509ExtendedTrustManager {

    private static final X500Principal PRIVATE_ISSUER = new X500Principal("CN=Sulake Oy Server Certificate Authority,OU=HH_intra_ALL,O=Sulake Oy,L=Helsinki,ST=Uusimaa,C=FI");
    private static final String LIVE_NAME = "game-*.habbo.com";
    private static final String DEVELOPMENT_NAME = "habbo-local-dev-server.sulake.com";
    private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

    private final X509ExtendedTrustManager delegate;

    UnityInnerTlsTrust() throws Exception {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        X509TrustManager selected = null;
        for (var manager : factory.getTrustManagers()) {
            if (manager instanceof X509TrustManager trust) {
                selected = trust;
                break;
            }
        }
        if (!(selected instanceof X509ExtendedTrustManager extended)) {
            throw new IllegalStateException("Default extended trust manager is unavailable");
        }
        delegate = extended;
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        try {
            delegate.checkServerTrusted(chain, authType, engine);
        } catch (CertificateException exception) {
            validatePrivate(chain, authType, engine.getPeerHost());
        }
    }

    private static void validatePrivate(X509Certificate[] chain, String authType, String host) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Inner TLS did not provide a certificate");
        }
        X509Certificate leaf = chain[0];
        leaf.checkValidity();
        if (!"ECDHE_RSA".equals(authType) || !"RSA".equalsIgnoreCase(leaf.getPublicKey().getAlgorithm())) {
            throw new CertificateException("Inner TLS certificate algorithm is not accepted");
        }
        if (!PRIVATE_ISSUER.equals(leaf.getIssuerX500Principal())) {
            throw new CertificateException("Inner TLS issuer is not accepted");
        }
        if (leaf.getBasicConstraints() != -1) {
            throw new CertificateException("Inner TLS leaf is a certificate authority");
        }
        List<String> usage = leaf.getExtendedKeyUsage();
        if (usage != null && !usage.contains(SERVER_AUTH)) {
            throw new CertificateException("Inner TLS certificate is not valid for servers");
        }
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && (keyUsage.length == 0 || !keyUsage[0])) {
            throw new CertificateException("Inner TLS certificate cannot sign the handshake");
        }
        if (!allowedName(host) || !certificateMatches(leaf, host)) {
            throw new CertificateException("Inner TLS certificate name is not accepted");
        }
    }

    private static boolean allowedName(String host) {
        return wildcard(LIVE_NAME, host) || DEVELOPMENT_NAME.equalsIgnoreCase(host);
    }

    private static boolean certificateMatches(X509Certificate certificate, String host) throws CertificateException {
        try {
            Collection<List<?>> alternatives = certificate.getSubjectAlternativeNames();
            if (alternatives != null) {
                boolean dnsPresent = false;
                for (List<?> alternative : alternatives) {
                    if (alternative.size() < 2
                            || !(alternative.get(0) instanceof Integer kind)
                            || kind != 2
                            || !(alternative.get(1) instanceof String name)) {
                        continue;
                    }
                    dnsPresent = true;
                    if (wildcard(name, host)) {
                        return true;
                    }
                }
                if (dnsPresent) {
                    return false;
                }
            }
            String subject = certificate.getSubjectX500Principal().getName();
            for (String part : subject.split(",")) {
                String value = part.trim();
                if (value.regionMatches(true, 0, "CN=", 0, 3) && wildcard(value.substring(3), host)) {
                    return true;
                }
            }
            return false;
        } catch (Exception exception) {
            throw new CertificateException(exception);
        }
    }

    static boolean wildcard(String template, String host) {
        if (template == null || host == null || template.isBlank() || host.isBlank()) {
            return false;
        }
        String[] expected = template.toLowerCase(Locale.ROOT).split("\\.", -1);
        String[] actual = host.toLowerCase(Locale.ROOT).split("\\.", -1);
        if (expected.length != actual.length) {
            return false;
        }
        for (int index = 0; index < expected.length; index++) {
            if (!wildcardLabel(expected[index], actual[index])) {
                return false;
            }
        }
        return true;
    }

    private static boolean wildcardLabel(String template, String value) {
        int templateIndex = 0;
        int valueIndex = 0;
        int wildcardIndex = -1;
        int retryIndex = -1;
        while (valueIndex < value.length()) {
            if (templateIndex < template.length() && template.charAt(templateIndex) == value.charAt(valueIndex)) {
                templateIndex++;
                valueIndex++;
            } else if (templateIndex < template.length() && template.charAt(templateIndex) == '*') {
                wildcardIndex = templateIndex++;
                retryIndex = valueIndex;
            } else if (wildcardIndex >= 0) {
                templateIndex = wildcardIndex + 1;
                valueIndex = ++retryIndex;
            } else {
                return false;
            }
        }
        while (templateIndex < template.length() && template.charAt(templateIndex) == '*') {
            templateIndex++;
        }
        return templateIndex == template.length();
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        delegate.checkServerTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, engine);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}
