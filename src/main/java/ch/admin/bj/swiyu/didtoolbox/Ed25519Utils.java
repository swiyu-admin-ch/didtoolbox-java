package ch.admin.bj.swiyu.didtoolbox;

import io.ipfs.multibase.Base58;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
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
     * The length of byte array representing an Ed25519 public key as specified by the
     * <a href="https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.5">RFC 8032</a> standard
     */
    final private static int PUBLIC_KEY_LENGTH = 32;

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
        if (len != PUBLIC_KEY_LENGTH)
            throw new IllegalArgumentException("The supplied Ed25519 public key must be of length 32 (bytes), but got " + len);

        final var reversed = reverse(ed25519publicKey, 0, PUBLIC_KEY_LENGTH);
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
     * A convenient package-scope weak-typing encoding helper.
     * <p>
     * The encoding of an Ed25519 public key MUST start with the two-byte prefix 0xed01 (the varint expression of 0xed),
     * followed by the 32-byte public key data. The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
     * and then prepended with the <a href="https://www.w3.org/TR/controller-document/#multibase-0">base-58-btc Multibase header (z)</a>.
     * </p>
     * <p>See <a href="https://www.w3.org/TR/controller-document/#Multikey">Multikey</a></p>
     *
     * @param publicKeyEncoded Ed25519 public key in its primary encoding format as in {@link PublicKey#getEncoded()}
     * @return multibase encoded Ed25519 public key
     */
    static String encodeMultibase(byte[] publicKeyEncoded) {

        var len = publicKeyEncoded.length;
        if (len < PUBLIC_KEY_LENGTH)
            throw new IllegalArgumentException("The supplied encoded Ed25519 public key must be at least of length 32 (bytes), but got " + len);

        // See https://github.com/multiformats/multicodec/blob/master/table.csv#L98
        var buff = ByteBuffer.allocate(PUBLIC_KEY_LENGTH + 2)
                .put((byte) 0xed) // Ed25519Pub/ed25519-pub is a draft code tagged "key" and described by: Ed25519 public key.
                .put((byte) 0x01)
                .put(Arrays.copyOfRange(publicKeyEncoded, publicKeyEncoded.length - 32, publicKeyEncoded.length));

        return 'z' + Base58.encode(buff.array());
    }

    /**
     * A convenient strict/strong-typing encoding helper.
     *
     * @param publicKey Ed25519 public key to encode as multibase
     * @return multibase encoded Ed25519 public key
     * @throws IllegalArgumentException if the supplied public key does not support encoding
     * @see #encodeMultibase(byte[])
     */
    public static String encodeMultibase(PublicKey publicKey) {
        byte[] publicKeyEncoded = publicKey.getEncoded();
        if (publicKeyEncoded == null) {
            throw new IllegalArgumentException("The supplied public key does not support encoding");
        }
        return encodeMultibase(publicKeyEncoded);
    }

    /**
     * <p>
     * Decodes a multibase key into the 32-byte public key data.
     * The multikey has the prefix 'z' followed by 34-byte data encoded using the base-58-btc alphabet.
     * Of those data bytes, the first 2 denote the variant of the key and the rest being the key data.
     * </p>
     * <p>See <a href="https://www.w3.org/TR/controller-document/#Multikey">Multikey</a></p>
     * <p>This method can fail, throwing an {@link IllegalArgumentException} when the provided multibase string is not supported.</p>
     *
     * @param multibase is a publicKey encoded as multibase
     * @return publicKey
     */
    public static byte[] decodePublicKeyMultibase(String multibase) {
        if (multibase.isEmpty() || multibase.charAt(0) != 'z') {
            throw new IllegalArgumentException();
        }
        var buf = Base58.decode(multibase.substring(1));

        // See https://github.com/multiformats/multicodec/blob/master/table.csv#L98
        if (buf[0] == (byte) 0xed && buf[1] == (byte) 0x01) {// Ed25519Pub/ed25519-pub is a draft code tagged "key" and described by: Ed25519 public key.
            return Arrays.copyOfRange(buf, 2, buf.length);
        }

        throw new IllegalArgumentException("Only Ed25519 public key is supported");
    }

    public static byte[] decodePrivateKeyMultibase(String multibase) {
        if (multibase.isEmpty() || multibase.charAt(0) != 'z') {
            throw new IllegalArgumentException();
        }
        var buf = Base58.decode(multibase.substring(1));

        // As specified by [Multikey]:
        //
        // The encoding of an Ed25519 secret key MUST start with the two-byte prefix 0x8026 (the varint expression of 0x1300),
        // followed by the 32-byte secret key data. The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
        // according to Section 2.4 Multibase (https://www.w3.org/TR/controller-document/#multibase-0),
        // and then prepended with the base-58-btc Multibase header (z).
        //
        // [Multikey]: https://www.w3.org/TR/controller-document/#Multikey
        //
        // See https://github.com/multiformats/multicodec/blob/master/table.csv#L187
        if (buf[0] == (byte) 0x80 && buf[1] == (byte) 0x26) {
            return Arrays.copyOfRange(buf, 2, buf.length);
        }

        throw new IllegalArgumentException("Only Ed25519 private key is supported");
    }
}