package ch.admin.bj.swiyu.didtoolbox;

import com.nimbusds.jose.util.Base64;
import io.ipfs.multibase.Base58;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class Ed25519UtilsTest extends AbstractUtilTestBase {

    private static Collection<Object[]> publicKeyMultibase() {
        return Arrays.asList(new String[][]{
                /*
                All lines in the private/public matrix were generated using openssl command by running the following script:

                openssl genpkey -algorithm ed25519 -out private.pem
                openssl pkey -inform pem -in private.pem -outform der -out private.der
                cat private.pem | openssl pkey -pubout -outform der -out public.der
                public_key_multibase=z$(echo ed01$(xxd -plain -cols 32 -s -32 public.der)  | xxd -r -p | bs58)
                echo "{\"${public_key_multibase}\"}"
                 */
                {"z6MkrBQ9BhY6odonjhdwpkZ5eD7BawVXiyR1S24wsD7xXvPS"},
                {"z6Mkwf4PgXLq8sRfucTggtZXmigKZP7gQhFamk3XHGV54QvF"},
                {"z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"},
        });
    }

    /**
     * As specified by <a href="https://datatracker.ietf.org/doc/html/rfc8032#section-7.1">Test Vectors for Ed25519</a>
     */
    private static Collection<Object[]> testVectorPublicKeys() {
        return Arrays.asList(new String[][]{
                // RFC 8032 test vector #1
                {"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"},
                // RFC 8032 test vector #2
                {"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"},
                // RFC 8032 test vector #3
                {"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"},
                // RFC 8032 test vector #4
                {"278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"},
                // RFC 8032 test vector #5
                {"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"},
        });
    }

    @DisplayName("Converting various multibase encoded public keys")
    @ParameterizedTest(name = "Converting key: {0}")
    @MethodSource("publicKeyMultibase")
    void testToPublicKey(String publicKeyMultibase) {

        var decoded = Base58.decode(publicKeyMultibase.substring(1));

        PublicKey actual = assertDoesNotThrow(() -> {
            return Ed25519Utils.toPublicKey(ByteBuffer.allocate(32)
                    .put(Arrays.copyOfRange(decoded, decoded.length - 32, decoded.length))
                    .array()); // MUT
        });

        assertNotNull(actual);
        assertEquals("EdDSA", actual.getAlgorithm());
        assertEquals("X.509", actual.getFormat());
        assertEquals(44, actual.getEncoded().length);
        assertEquals(publicKeyMultibase, Ed25519Utils.encodeMultibase(actual));
    }

    @DisplayName("Converting various test vector public keys")
    @ParameterizedTest(name = "Converting key: {0}")
    @MethodSource("testVectorPublicKeys")
    void testToPublicKeyUsingTestVectorsPKs(String testVectorPublicKey) {

        PublicKey actual = assertDoesNotThrow(() -> {
            return Ed25519Utils.toPublicKey(HexFormat.of().parseHex(testVectorPublicKey)); // MUT
        });

        assertNotNull(actual);
        assertEquals("EdDSA", actual.getAlgorithm());
        assertEquals("X.509", actual.getFormat());

        var encoded = actual.getEncoded();

        assertEquals(44, encoded.length);

        assertEquals(testVectorPublicKey, HexFormat.of().formatHex(
                ByteBuffer.allocate(32)
                        .put(Arrays.copyOfRange(encoded, 12, encoded.length)).array()));
    }

    @DisplayName("Intentionally throwing IllegalArgumentException")
    @ParameterizedTest(name = "Using key: {0}")
    @MethodSource("testVectorPublicKeys")
    void testToPublicKeyUsingTestVectorsPKsThrowsIllegalArgumentException(String testVectorPublicKey) {

        var pk = HexFormat.of().parseHex(testVectorPublicKey);

        assertThrowsExactly(IllegalArgumentException.class, () -> {
            Ed25519Utils.toPublicKey(ByteBuffer.allocate(33)
                    .put(pk) // 32 canonical bytes
                    .put((byte) 0x00) // CAUTION Rather harmless pad
                    .array()); // MUT
        });

        assertThrowsExactly(IllegalArgumentException.class, () -> {
            Ed25519Utils.toPublicKey(ByteBuffer.allocate(31)
                    .put(Arrays.copyOfRange(pk, 0, pk.length - 1)) // a bit shorter canonical key
                    .array()); // MUT
        });
    }

    @DisplayName("Decode and encode again various multibase encoded public keys")
    @ParameterizedTest(name = "Converting key: {0}")
    @MethodSource("publicKeyMultibase")
    void testFromMultibase(String publicKeyMultibase) throws InvalidAlgorithmParameterException {
        var decoded = Ed25519Utils.decodeMultibase(publicKeyMultibase);
        var encoded = Ed25519Utils.encodeMultibase(decoded);
        assertEquals(publicKeyMultibase, encoded);
    }

    @DisplayName("Attempt to decode various invalid Multibase")
    @Test
    void testFromMultibaseWithInvalidValues() throws Exception {
        var nonMultibaseValue = "just some random string";
        assertThrowsExactly(IllegalArgumentException.class, () -> Ed25519Utils.decodeMultibase(nonMultibaseValue));

        var emptyMultibaseValue = "";
        assertThrowsExactly(IllegalArgumentException.class, () -> Ed25519Utils.decodeMultibase(emptyMultibaseValue));

        var missingPrefixMultibaseValue = "6MkrBQ9BhY6odonjhdwpkZ5eD7BawVXiyR1S24wsD7xXvPS";
        assertThrowsExactly(IllegalArgumentException.class, () -> Ed25519Utils.decodeMultibase(missingPrefixMultibaseValue));

        var buff = ByteBuffer.allocate(34);
        buff.put((byte) 0xed);
        buff.put((byte) 0x01);
        buff.put(Arrays.copyOfRange(TEST_PUBLIC_KEY_ANOTHER, 0, TEST_PUBLIC_KEY_ANOTHER.length));
        // base64, see https://github.com/multiformats/multibase/blob/master/multibase.csv#L23
        var base64MultibaseValue = "m" + Base64.encode(buff.array());
        assertThrowsExactly(IllegalArgumentException.class, () -> Ed25519Utils.decodeMultibase(base64MultibaseValue));

        buff = ByteBuffer.allocate(34);
        // private key Ed25519, see https://github.com/multiformats/multicodec/blob/master/table.csv#L182
        buff.put((byte) 0x13);
        buff.put((byte) 0x00);
        buff.put(Arrays.copyOfRange(TEST_PRIVATE_KEY_ANOTHER, 0, TEST_PRIVATE_KEY_ANOTHER.length));
        var unsupportedTypeMultibaseValue = "z" + Base58.encode(buff.array());
        assertThrowsExactly(IllegalArgumentException.class, () -> Ed25519Utils.decodeMultibase(unsupportedTypeMultibaseValue));
    }
}
