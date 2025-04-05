package ch.admin.bj.swiyu.didtoolbox;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;

class Ed25519Utils {

    static int PUBLIC_KEY_LENGTH = 32;

    private Ed25519Utils() {
    }

    static PublicKey toJavaSecurityPublicKey(final byte[] publicKey, final int off, final int len) {
        final var reversed = reverse(publicKey, off, len);
        final int last = reversed[0] & 0xFF;
        final boolean xOdd = (last & 0b1000_0000) == 0b1000_0000;
        reversed[0] = (byte) (last & Byte.MAX_VALUE);
        final var y = new BigInteger(reversed);
        final var edECPoint = new EdECPoint(xOdd, y);
        final var pubSpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, edECPoint);
        try {
            // CAUTION The "BC" (BouncyCastleProvider) provider fails while calling generatePublic(...)
            var fact = KeyFactory.getInstance("Ed25519"); // default provider -> "SunEC"
            return fact.generatePublic(pubSpec);
        } catch (final InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static PublicKey toJavaSecurityPublicKey(final byte[] publicKey) {
        return toJavaSecurityPublicKey(publicKey, 0, PUBLIC_KEY_LENGTH);
    }

    private static byte[] reverse(final byte[] bytes, final int offset, final int len) {
        final byte[] reversed = new byte[len];
        for (int i = offset, j = (offset + len) - 1; j >= offset; ++i, --j) {
            reversed[j] = bytes[i];
        }
        return reversed;
    }
}