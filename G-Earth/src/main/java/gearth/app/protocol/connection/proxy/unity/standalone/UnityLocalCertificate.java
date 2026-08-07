package gearth.app.protocol.connection.proxy.unity.standalone;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

final class UnityLocalCertificate {

    private static final char[] PASSWORD = "gearth-unity-local".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path directory;

    UnityLocalCertificate(Path directory) {
        this.directory = directory;
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    SSLContext serverContext(String host) throws Exception {
        Files.createDirectories(directory);
        KeyMaterial material = loadOrCreate(host);
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("server", material.privateKey(), PASSWORD, new Certificate[]{material.certificate()});
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(store, PASSWORD);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(managers.getKeyManagers(), null, RANDOM);
        return context;
    }

    private KeyMaterial loadOrCreate(String host) throws Exception {
        Path privatePath = directory.resolve("server-private.der");
        Path certificatePath = directory.resolve("server.crt");
        if (Files.isRegularFile(privatePath) && Files.isRegularFile(certificatePath)) {
            try {
                KeyMaterial material = load(privatePath, certificatePath);
                material.certificate().checkValidity();
                if (material.privateKey() instanceof RSAPrivateKey privateKey
                        && material.certificate().getPublicKey() instanceof RSAPublicKey publicKey
                        && privateKey.getModulus().equals(publicKey.getModulus())) {
                    return material;
                }
            } catch (Exception ignored) {
            }
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, RANDOM);
        KeyPair pair = generator.generateKeyPair();
        Instant now = Instant.now();
        X500Name subject = new X500Name("CN=" + host);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                new BigInteger(159, RANDOM).setBit(158),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(3650, ChronoUnit.DAYS)),
                subject,
                pair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.iPAddress, host)));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(pair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
        certificate.checkValidity();
        Files.write(privatePath, pair.getPrivate().getEncoded());
        Files.write(certificatePath, certificate.getEncoded());
        return new KeyMaterial(pair.getPrivate(), certificate);
    }

    private static KeyMaterial load(Path privatePath, Path certificatePath) throws Exception {
        PrivateKey privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privatePath)));
        try (var input = Files.newInputStream(certificatePath)) {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
            return new KeyMaterial(privateKey, certificate);
        }
    }

    private record KeyMaterial(PrivateKey privateKey, X509Certificate certificate) {
    }
}
