package ch.admin.bj.swiyu.didtoolbox;

import io.ipfs.multibase.Base58;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

/**
 * A helper class featuring various convenient conversion methods with
 * <a href="https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5">RFC 8032</a> standard in mind
 */
public final class Ed25519Utils {

    /**
     * The length of byte array representing an Ed25519 key as specified by the
     * <a href="https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5">RFC 8032</a> standard
     */
    final private static int ED25519_KEY_LENGTH = 32;

    private Ed25519Utils() {
    }

    /**
     * A convenient strict/strong-typing conversion helper.
     *
     * @param ed25519publicKey 32-length byte array representing an Ed25519 public key as specified by the
     *                         <a href="https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5">RFC 8032</a> standard
     * @return an instance of {@link PublicKey}
     * @throws NoSuchAlgorithmException if no {@code Provider} supports a {@code KeyFactorySpi} implementation for the specified algorithm
     * @throws InvalidKeySpecException  if the given key specification is inappropriate for this key factory to produce a public key
     */
    static PublicKey toPublicKey(final byte[] ed25519publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        var len = ed25519publicKey.length;
        if (len != ED25519_KEY_LENGTH)
            throw new IllegalArgumentException("The supplied Ed25519 public key must be of length 32 (bytes), but got " + len);

        final var reversed = reverse(ed25519publicKey, 0, ED25519_KEY_LENGTH);
        final int last = reversed[0] & 0xFF;
        final boolean xOdd = (last & 0b1000_0000) == 0b1000_0000;
        reversed[0] = (byte) (last & Byte.MAX_VALUE);

        final var y = new BigInteger(reversed);
        // CAUTION The "BC" (BouncyCastleProvider) provider fails while calling generatePublic(...)
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y))); // default provider -> "SunEC"
    }

    private static byte[] reverse(final byte[] bytes, final int offset, final int len) {
        final byte[] reversed = new byte[len];
        for (int i = offset, j = (offset + len) - 1; j >= offset; ++i, --j) {
            reversed[j] = bytes[i];
        }
        return reversed;
    }

    /**
     * A convenient encoding helper implementing <a href="https://www.w3.org/TR/cid/#Multikey">Multikey</a> formatting of Ed25519 keys.
     * <p>
     * The encoding of an Ed25519 public key MUST start with the two-byte prefix 0xed01 (the varint expression of 0xed),
     * followed by the 32-byte public key data. The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
     * and then prepended with the <a href="https://www.w3.org/TR/cid/#multibase-0">base-58-btc Multibase header (z)</a>.
     * </p>
     * The encoding of an Ed25519 secret key MUST start with the two-byte prefix 0x8026 (the varint expression of 0x1300),
     * followed by the 32-byte secret key data. The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
     * according to <a href="https://www.w3.org/TR/cid/#multibase-0">Multibase</a>, and then prepended with the base-58-btc Multibase header (z).
     *
     * @param key Ed25519 (either private or public) key to encode. It is assumed the key supports its primary encoding format.
     *            Otherwise, {@link IllegalArgumentException} is thrown
     * @return multibase encoded Ed25519 key
     */
    public static String toMultibase(Key key) {

        byte[] keyEncoded = key.getEncoded();
        if (keyEncoded == null) {
            throw new IllegalArgumentException("The supplied key does not support encoding");
        }

        var len = keyEncoded.length;
        if (len < ED25519_KEY_LENGTH)
            throw new IllegalArgumentException("The supplied Ed25519 key must be at least of length 32 (bytes), but got " + len);

        var buff = ByteBuffer.allocate(ED25519_KEY_LENGTH + 2);
        switch (key) {
            case PublicKey ignored:
                buff.put((byte) 0xed).put((byte) 0x01);
                break;
            case PrivateKey ignored:
                buff.put((byte) 0x80).put((byte) 0x26);
                break;
            default:
                throw new IllegalArgumentException("The supplied Ed25519 must be either private or public");
        }

        buff.put(Arrays.copyOfRange(keyEncoded, keyEncoded.length - 32, keyEncoded.length));

        return 'z' + Base58.encode(buff.array());
    }
}