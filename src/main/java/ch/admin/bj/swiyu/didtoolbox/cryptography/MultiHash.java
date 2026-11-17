package ch.admin.bj.swiyu.didtoolbox.cryptography;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class MultiHash {

    private MultiHash() {
    }

    /**
     * multihash is an implementation of the <a href="https://www.w3.org/TR/controller-document/#multihash">multihash</a> specification.
     * Its output is a hash of the input using the associated <a href="https://www.rfc-editor.org/rfc/rfc6234">hash algorithm</a>,
     * prefixed with a hash algorithm identifier and the hash size.
     *
     * @param input string to be hashed
     * @return {@code input} string hashed accordingly
     */
    public static byte[] multihash(String input) {
        return multihash(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * multihash is an implementation of the <a href="https://www.w3.org/TR/controller-document/#multihash">multihash</a> specification.
     * Its output is a hash of the input using the associated {@code <hash algorithm>}, prefixed with a hash algorithm identifier and the hash size.
     *
     * @param input the array of bytes to be hashed.
     * @return hashed bytes
     */
    static byte[] multihash(byte[] input) {
        MessageDigest hasher;
        try {
            hasher = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        hasher.update(input);
        byte[] digest = hasher.digest();

        // multihash is an implementation of the multihash specification (https://www.w3.org/TR/controller-document/#multihash).
        // Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
        // Multihash Identifier	Multihash Header	Description
        // sha2-256	            0x12	            SHA-2 with 256 bits (32 bytes) of output, as defined by [RFC6234].
        ByteBuffer buff = ByteBuffer.allocate(2 + digest.length);
        buff.put((byte) 0x12);          // hash algorithm (sha2-256) identifier
        buff.put((byte) digest.length); // hash size (in bytes)
        buff.put(digest);

        return buff.array();
    }
}
