package gearth.app.protocol.connection.proxy.unity.standalone;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

final class UnityStandaloneCrypto {

    static final String SERVER_MODULUS = "BD214E4F036D35B75FEE36000F24EBBEF15D56614756D7AFBD4D186EF5445F758B284647FEB773927418EF70B95387B80B961EA56D8441D410440E3D3295539A3E86E7707609A274C02614CC2C7DF7D7720068F072E098744AFE68485C6297893F3D2BA3D7AAAAF7FA8EBF5D7AF0BA2D42E0D565B89D332DE4CF898D666096CE61698DE0FAB03A8A5E12430CB427C97194CBD221843D162C9F3ACF74DA1D80EBC37FDE442B68A0814DFEA3989FDF8129C120A8418248D7EE85D0B79FA818422E496D6FA7B5BD5DB77E588F8400CDA1A8D82EFED6C86B434BAFA6D07DFCC459D35D773F8DFAF523DFED8FCA45908D0F9ED0D4BCEAC3743AF39F11310EAF3DFF45";
    static final BigInteger SERVER_EXPONENT = BigInteger.valueOf(65537);

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private UnityStandaloneCrypto() {
    }

    static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, RANDOM);
        while (true) {
            KeyPair keyPair = generator.generateKeyPair();
            if (keyPair.getPublic() instanceof java.security.interfaces.RSAPublicKey publicKey
                    && publicKey.getModulus().toString(16).length() == SERVER_MODULUS.length()) {
                return keyPair;
            }
        }
    }

    static String encodeInteger(BigInteger value, int paddingType, BigInteger exponent, BigInteger modulus) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("RSA integer must not be negative");
        }
        return encode(value.toString().getBytes(StandardCharsets.US_ASCII), paddingType, exponent, modulus);
    }

    static BigInteger decodeInteger(String value, BigInteger exponent, BigInteger modulus) {
        byte[] decoded = decode(value, exponent, modulus);
        if (decoded.length == 0) {
            throw new IllegalArgumentException("RSA integer is empty");
        }
        for (byte digit : decoded) {
            if (digit < '0' || digit > '9') {
                throw new IllegalArgumentException("RSA integer is not decimal");
            }
        }
        return new BigInteger(new String(decoded, StandardCharsets.US_ASCII));
    }

    static BigInteger randomInteger(BigInteger modulus) {
        int length = (modulus.bitLength() - 2) / 8;
        if (length <= 0) {
            throw new IllegalArgumentException("DH modulus is too small");
        }
        byte[] littleEndian = new byte[length];
        BigInteger value;
        do {
            RANDOM.nextBytes(littleEndian);
            littleEndian[littleEndian.length - 1] &= 0x7f;
            byte[] bigEndian = new byte[littleEndian.length];
            for (int index = 0; index < littleEndian.length; index++) {
                bigEndian[index] = littleEndian[littleEndian.length - index - 1];
            }
            value = new BigInteger(1, bigEndian);
        } while (value.signum() == 0);
        return value;
    }

    static byte[] key(BigInteger sharedSecret) {
        byte[] encoded = sharedSecret.toByteArray();
        if (encoded.length > 32) {
            throw new IllegalArgumentException("Shared secret does not fit the Unity key buffer");
        }
        return Arrays.copyOf(encoded, 32);
    }

    private static String encode(byte[] message, int paddingType, BigInteger exponent, BigInteger modulus) {
        if (paddingType != 1 && paddingType != 2) {
            throw new IllegalArgumentException("Unsupported RSA padding type");
        }
        int modulusLength = (modulus.bitLength() + 7) / 8;
        int blockLength = modulusLength - 1;
        if (message.length > blockLength - 11) {
            throw new IllegalArgumentException("RSA payload is too large");
        }
        byte[] block = new byte[blockLength];
        block[0] = (byte) paddingType;
        int delimiter = block.length - message.length - 1;
        for (int index = 1; index < delimiter; index++) {
            if (paddingType == 1) {
                block[index] = (byte) 0xff;
            } else {
                do {
                    block[index] = (byte) RANDOM.nextInt(256);
                } while (block[index] == 0);
            }
        }
        System.arraycopy(message, 0, block, delimiter + 1, message.length);
        BigInteger encoded = new BigInteger(1, block).modPow(exponent, modulus);
        byte[] raw = unsigned(encoded.toByteArray());
        if (raw.length > modulusLength) {
            throw new IllegalStateException("RSA result exceeds its modulus width");
        }
        return HEX.formatHex(raw);
    }

    private static byte[] decode(String value, BigInteger exponent, BigInteger modulus) {
        BigInteger encoded = new BigInteger(1, HEX.parseHex(value));
        byte[] block = unsigned(encoded.modPow(exponent, modulus).toByteArray());
        int delimiter = -1;
        for (int index = 1; index < block.length; index++) {
            if (block[index] == 0) {
                delimiter = index;
                break;
            }
        }
        if (delimiter < 9 || delimiter + 1 >= block.length) {
            throw new IllegalArgumentException("Invalid RSA padding");
        }
        return Arrays.copyOfRange(block, delimiter + 1, block.length);
    }

    private static byte[] unsigned(byte[] bytes) {
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}
