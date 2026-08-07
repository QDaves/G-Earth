package gearth.app.protocol.connection.proxy.unity.standalone;

import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HexFormat;

final class UnityHandshakeTranslator {

    private static final HexFormat HEX = HexFormat.of();

    private final UnityHandshakeHeaders headers;
    private final BigInteger serverExponent;
    private final BigInteger serverModulus;
    private final RSAPrivateCrtKey localPrivate;
    private final RSAPublicKey localPublic;

    private byte[] nonce;
    private BigInteger prime;
    private BigInteger generator;
    private BigInteger clientPublic;
    private BigInteger clientSecret;
    private BigInteger serverSecret;
    private HeaderCipher clientReader;
    private HeaderCipher clientWriter;
    private HeaderCipher serverReader;
    private HeaderCipher serverWriter;

    UnityHandshakeTranslator(
            UnityHandshakeHeaders headers,
            RSAPrivateCrtKey localPrivate,
            RSAPublicKey localPublic) {
        this.headers = headers;
        this.serverExponent = UnityStandaloneCrypto.SERVER_EXPONENT;
        this.serverModulus = new BigInteger(UnityStandaloneCrypto.SERVER_MODULUS, 16);
        this.localPrivate = localPrivate;
        this.localPublic = localPublic;
        if (!localPrivate.getModulus().equals(localPublic.getModulus())) {
            throw new IllegalArgumentException("Local RSA key pair mismatch");
        }
    }

    DecodedPacket receiveClient(byte[] frame) {
        byte[] plain = frame.clone();
        if (clientReader != null) {
            clientReader.apply(plain);
        }
        int header = header(plain);
        byte[] destination = plain;
        if (header == headers.clientHello()) {
            destination = rememberNonce(plain);
        } else if (header == headers.clientDhComplete()) {
            destination = translateClientPublic(plain);
        }
        return new DecodedPacket(header, plain, destination, isHandshake(header));
    }

    DecodedPacket receiveServer(byte[] frame) {
        byte[] plain = frame.clone();
        if (serverReader != null) {
            serverReader.apply(plain);
        }
        int header = header(plain);
        byte[] destination = plain;
        if (header == headers.serverDhInit()) {
            destination = translateParameters(plain);
        } else if (header == headers.serverDhComplete()) {
            destination = translateServerPublic(plain);
        }
        return new DecodedPacket(header, plain, destination, isHandshake(header));
    }

    byte[] sendToClient(byte[] frame, boolean encrypt) {
        byte[] wire = frame.clone();
        if (encrypt && clientWriter != null) {
            clientWriter.apply(wire);
        }
        return wire;
    }

    byte[] sendToServer(byte[] frame, boolean encrypt) {
        byte[] wire = frame.clone();
        if (encrypt && serverWriter != null) {
            serverWriter.apply(wire);
        }
        return wire;
    }

    boolean active() {
        return clientReader != null && clientWriter != null && serverReader != null && serverWriter != null;
    }

    static String clientIdentifier(byte[] hello) {
        PacketReader reader = new PacketReader(hello);
        reader.readString();
        return reader.readString();
    }

    private byte[] rememberNonce(byte[] frame) {
        PacketReader reader = new PacketReader(frame);
        String encodedNonce = reader.readString();
        String identifier = reader.readString();
        if (!validClientIdentifier(identifier)) {
            throw new IllegalArgumentException("Unexpected client identifier: " + identifier);
        }
        nonce = decodeNonce(encodedNonce);
        return frame;
    }

    private byte[] translateParameters(byte[] frame) {
        requireNonce();
        PacketReader reader = new PacketReader(frame);
        prime = UnityStandaloneCrypto.decodeInteger(reader.readString(), serverExponent, serverModulus);
        generator = UnityStandaloneCrypto.decodeInteger(reader.readString(), serverExponent, serverModulus);
        validateParameters(prime, generator);
        clientSecret = UnityStandaloneCrypto.randomInteger(prime);
        serverSecret = UnityStandaloneCrypto.randomInteger(prime);
        String localPrime = UnityStandaloneCrypto.encodeInteger(prime, 1, localPrivate.getPrivateExponent(), localPrivate.getModulus());
        String localGenerator = UnityStandaloneCrypto.encodeInteger(generator, 1, localPrivate.getPrivateExponent(), localPrivate.getModulus());
        return packet(headers.serverDhInit(), writer -> writer.writeString(localPrime).writeString(localGenerator));
    }

    private byte[] translateClientPublic(byte[] frame) {
        requireParameters();
        PacketReader reader = new PacketReader(frame);
        clientPublic = UnityStandaloneCrypto.decodeInteger(reader.readString(), localPrivate.getPrivateExponent(), localPrivate.getModulus());
        validatePublic(clientPublic);
        BigInteger serverLegPublic = generator.modPow(serverSecret, prime);
        String encrypted = UnityStandaloneCrypto.encodeInteger(serverLegPublic, 2, serverExponent, serverModulus);
        return packet(headers.clientDhComplete(), writer -> writer.writeString(encrypted));
    }

    private byte[] translateServerPublic(byte[] frame) {
        requireClientPublic();
        PacketReader reader = new PacketReader(frame);
        BigInteger serverPublic = UnityStandaloneCrypto.decodeInteger(reader.readString(), serverExponent, serverModulus);
        boolean bidirectional = reader.readBoolean();
        validatePublic(serverPublic);
        BigInteger clientLegPublic = generator.modPow(clientSecret, prime);
        BigInteger clientShared = clientPublic.modPow(clientSecret, prime);
        BigInteger serverShared = serverPublic.modPow(serverSecret, prime);
        String signed = UnityStandaloneCrypto.encodeInteger(clientLegPublic, 1, localPrivate.getPrivateExponent(), localPrivate.getModulus());
        initializeCiphers(clientShared, serverShared);
        return packet(headers.serverDhComplete(), writer -> writer.writeString(signed).writeBoolean(bidirectional));
    }

    private void initializeCiphers(BigInteger clientShared, BigInteger serverShared) {
        clientReader = new HeaderCipher(UnityStandaloneCrypto.key(clientShared), nonce);
        clientWriter = new HeaderCipher(UnityStandaloneCrypto.key(clientShared), nonce);
        serverReader = new HeaderCipher(UnityStandaloneCrypto.key(serverShared), nonce);
        serverWriter = new HeaderCipher(UnityStandaloneCrypto.key(serverShared), nonce);
    }

    private void requireNonce() {
        if (nonce == null) {
            throw new IllegalStateException("Hello must be received before DH parameters");
        }
    }

    private void requireParameters() {
        if (prime == null || generator == null || clientSecret == null || serverSecret == null) {
            throw new IllegalStateException("DH parameters must be received before the client public value");
        }
    }

    private void requireClientPublic() {
        requireParameters();
        if (clientPublic == null) {
            throw new IllegalStateException("Client public value must be received before the server public value");
        }
    }

    private static void validateParameters(BigInteger prime, BigInteger generator) {
        if (prime.signum() <= 0 || !prime.testBit(0) || prime.bitLength() < 128 || !prime.isProbablePrime(80)) {
            throw new IllegalArgumentException("Invalid DH prime");
        }
        if (generator.compareTo(BigInteger.TWO) < 0 || generator.compareTo(prime.subtract(BigInteger.ONE)) >= 0) {
            throw new IllegalArgumentException("Invalid DH generator");
        }
    }

    private void validatePublic(BigInteger value) {
        if (value.compareTo(BigInteger.TWO) < 0 || value.compareTo(prime.subtract(BigInteger.ONE)) >= 0) {
            throw new IllegalArgumentException("Invalid DH public value");
        }
    }

    private static byte[] decodeNonce(String value) {
        if (value.length() != 24) {
            throw new IllegalArgumentException("Unity nonce must contain 24 characters");
        }
        StringBuilder raw = new StringBuilder(16);
        for (int index = 0; index < 8; index++) {
            raw.append(value, index * 3, index * 3 + 2);
        }
        return HEX.parseHex(raw.toString());
    }

    static int header(byte[] frame) {
        validateFrame(frame);
        return ((frame[4] & 0xff) << 8) | (frame[5] & 0xff);
    }

    boolean isClientHello(int header) {
        return header == headers.clientHello();
    }

    private boolean isHandshake(int header) {
        return header == headers.clientHello()
                || header == headers.clientDhInit()
                || header == headers.clientDhComplete()
                || header == headers.serverDhInit()
                || header == headers.serverDhComplete();
    }

    private static boolean validClientIdentifier(String identifier) {
        if (identifier == null || !identifier.startsWith("UNITY") || identifier.length() == 5) {
            return false;
        }
        for (int index = 5; index < identifier.length(); index++) {
            if (!Character.isDigit(identifier.charAt(index))) {
                return false;
            }
        }
        return true;
    }

    private static byte[] packet(int header, PacketWriterAction action) {
        PacketWriter writer = new PacketWriter();
        action.write(writer);
        byte[] body = writer.bytes();
        ByteBuffer frame = ByteBuffer.allocate(body.length + 6).order(ByteOrder.BIG_ENDIAN);
        frame.putInt(body.length + 2);
        frame.putShort((short) header);
        frame.put(body);
        return frame.array();
    }

    static void validateFrame(byte[] frame) {
        if (frame.length < 6) {
            throw new IllegalArgumentException("Frame is shorter than its header");
        }
        int declared = ByteBuffer.wrap(frame, 0, 4).order(ByteOrder.BIG_ENDIAN).getInt();
        if (declared < 2 || declared != frame.length - 4) {
            throw new IllegalArgumentException("Frame length mismatch");
        }
    }

    record DecodedPacket(int header, byte[] source, byte[] destination, boolean handshake) {
    }

    @FunctionalInterface
    private interface PacketWriterAction {
        void write(PacketWriter writer);
    }

    private static final class PacketReader {
        private final ByteBuffer input;

        private PacketReader(byte[] frame) {
            validateFrame(frame);
            input = ByteBuffer.wrap(frame, 6, frame.length - 6).order(ByteOrder.BIG_ENDIAN);
        }

        private String readString() {
            int length = Short.toUnsignedInt(input.getShort());
            if (length > input.remaining()) {
                throw new IllegalArgumentException("String exceeds packet body");
            }
            byte[] value = new byte[length];
            input.get(value);
            return new String(value, StandardCharsets.UTF_8);
        }

        private boolean readBoolean() {
            return input.get() != 0;
        }
    }

    private static final class PacketWriter {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();

        private PacketWriter writeString(String value) {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            if (bytes.length > 0xffff) {
                throw new IllegalArgumentException("String is too long");
            }
            output.write((bytes.length >>> 8) & 0xff);
            output.write(bytes.length & 0xff);
            output.writeBytes(bytes);
            return this;
        }

        private PacketWriter writeBoolean(boolean value) {
            output.write(value ? 1 : 0);
            return this;
        }

        private byte[] bytes() {
            return output.toByteArray();
        }
    }

    private static final class HeaderCipher {
        private final ChaChaEngine engine;

        private HeaderCipher(byte[] key, byte[] nonce) {
            engine = new ChaChaEngine();
            engine.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        }

        private void apply(byte[] frame) {
            validateFrame(frame);
            frame[5] = engine.returnByte(frame[5]);
            frame[4] = engine.returnByte(frame[4]);
        }
    }
}
