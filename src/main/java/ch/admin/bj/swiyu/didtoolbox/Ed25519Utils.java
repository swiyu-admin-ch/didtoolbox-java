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

public class Ed25519Utils {

    static int PUBLIC_KEY_LENGTH = 32;

    private Ed25519Utils() {
    }

    static PublicKey toPublicKey(final byte[] publicKey, final int off, final int len) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final var reversed = reverse(publicKey, off, len);
        final int last = reversed[0] & 0xFF;
        final boolean xOdd = (last & 0b1000_0000) == 0b1000_0000;
        reversed[0] = (byte) (last & Byte.MAX_VALUE);
        final var y = new BigInteger(reversed);
        // CAUTION The "BC" (BouncyCastleProvider) provider fails while calling generatePublic(...)
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y))); // default provider -> "SunEC"
    }

    static PublicKey toPublicKey(final byte[] publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return toPublicKey(publicKey, 0, PUBLIC_KEY_LENGTH);
    }

    private static byte[] reverse(final byte[] bytes, final int offset, final int len) {
        final byte[] reversed = new byte[len];
        for (int i = offset, j = (offset + len) - 1; j >= offset; ++i, --j) {
            reversed[j] = bytes[i];
        }
        return reversed;
    }

    /**
     * <p>
     * The encoding of an Ed25519 public key MUST start with the two-byte prefix 0xed01 (the variant expression of 0xed),
     * followed by the 32-byte public key data. The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
     * and then prepended with the <a href="https://www.w3.org/TR/controller-document/#multibase-0">base-58-btc Multibase header (z)</a>.
     * </p>
     * <p>See <a href="https://www.w3.org/TR/controller-document/#Multikey">Multikey</a></p>
     *
     * @param publicKeyEncoded
     * @return
     */
    public static String encodeMultibase(byte[] publicKeyEncoded) {

        ByteBuffer buff = ByteBuffer.allocate(34);
        // See https://github.com/multiformats/multicodec/blob/master/table.csv#L98
        buff.put((byte) 0xed); // Ed25519Pub/ed25519-pub is a draft code tagged "key" and described by: Ed25519 public key.
        buff.put((byte) 0x01);
        buff.put(Arrays.copyOfRange(publicKeyEncoded, publicKeyEncoded.length - 32, publicKeyEncoded.length));
        return 'z' + Base58.encode(buff.array());
    }

    /**
     * <p>
     * Decodes a multibase key into the 32-byte public key data.
     * The multikey has the prefix 'z' followed by 34-byte data encoded using the base-58-btc alphabet.
     * Of those data bytes, the first 2 denote the variant of the key and the rest being the key data.
     * </p>
     * <p>See <a href="https://www.w3.org/TR/controller-document/#Multikey">Multikey</a></p>
     *
     * @param multibase is a publicKey encoded as multibase
     * @return publicKey
     */
    public static byte[] decodeMultibase(String multibase) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (multibase.charAt(0) != 'z') {
            throw new IllegalArgumentException();
        }
        multibase = multibase.substring(1);
        var buf = Base58.decode(multibase);

        // See https://github.com/multiformats/multicodec/blob/master/table.csv#L98
        if (buf[0] == (byte)0xed && buf[1] == (byte)0x01) {// Ed25519Pub/ed25519-pub is a draft code tagged "key" and described by: Ed25519 public key.
            return Arrays.copyOfRange(buf, 2, buf.length);
        }
        throw new IllegalArgumentException();
    }

    /*
    public static PrivateKey getPrivateKeyFromJKS(InputStream jksFile, String password, String alias, String keyPassword) throws CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, KeyException {
        var provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        // CAUTION Calling KeyStore.getInstance("JKS") may cause:
        //         "java.security.NoSuchAlgorithmException: no such algorithm: EdDSA for provider SUN"
        KeyStore keyStore = KeyStore.getInstance("PKCS12", provider);
        char[] pass = null;
        if (password != null) {
            pass = password.toCharArray();
        }
        keyStore.load(jksFile, pass); // java.io.IOException: keystore password was incorrect

        // CAUTION Flexible constructors is a preview feature and is disabled by default. (use --enable-preview to enable flexible constructors)
        //this(createFromKeyStore(keyStore, alias, keyPassword));
        var obj = createFromKeyStore(keyStore, alias, keyPassword);
        var keyPair = obj.keyPair;
        return keyPair.getPrivate();
    }
     */
}