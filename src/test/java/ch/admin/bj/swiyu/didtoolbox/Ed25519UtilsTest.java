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

import static org.junit.jupiter.api.Assertions.*;

class Ed25519UtilsTest {

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

    @DisplayName("Converting various multibase encoded public keys")
    @ParameterizedTest(name = "Converting key: {0}")
    @MethodSource("publicKeyMultibase")
    void testToPublicKey(String publicKeyMultibase) {

        var decoded = Base58.decode(publicKeyMultibase.substring(1));
        var buff = ByteBuffer.allocate(32);
        buff.put(Arrays.copyOfRange(decoded, decoded.length - 32, decoded.length));

        PublicKey actual = assertDoesNotThrow(() -> {
            return Ed25519Utils.toPublicKey(buff.array()); // MUT
        });

        assertNotNull(actual);
        assertEquals("EdDSA", actual.getAlgorithm());
        assertEquals("X.509", actual.getFormat());
        assertEquals(44, actual.getEncoded().length);
        assertEquals(publicKeyMultibase, Ed25519Utils.encodeMultibase(actual.getEncoded()));
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
    void testFromMultibaseWithInvalidValues() throws GeneralSecurityException {
        var keyPair = com.google.crypto.tink.subtle.Ed25519Sign.KeyPair.newKeyPair();
        var privateKey = keyPair.getPrivateKey();
        var publicKey = keyPair.getPublicKey();

        var nonMultibaseValue = "just some random string";
        assertThrowsExactly(IllegalArgumentException.class, () -> Ed25519Utils.decodeMultibase(nonMultibaseValue));

        var emptyMultibaseValue = "";
        assertThrowsExactly(IllegalArgumentException.class, () -> Ed25519Utils.decodeMultibase(emptyMultibaseValue));

        var missingPrefixMultibaseValue = "6MkrBQ9BhY6odonjhdwpkZ5eD7BawVXiyR1S24wsD7xXvPS";
        assertThrowsExactly(IllegalArgumentException.class, () -> Ed25519Utils.decodeMultibase(missingPrefixMultibaseValue));

        var buff = ByteBuffer.allocate(34);
        buff.put((byte)0xed);
        buff.put((byte)0x01);
        buff.put(Arrays.copyOfRange(publicKey, 0, publicKey.length));
        // base64, see https://github.com/multiformats/multibase/blob/master/multibase.csv#L23
        var base64MultibaseValue = "m" + Base64.encode(buff.array());
        assertThrowsExactly(IllegalArgumentException.class, () -> Ed25519Utils.decodeMultibase(base64MultibaseValue));

        buff = ByteBuffer.allocate(34);
        // private key Ed25519, see https://github.com/multiformats/multicodec/blob/master/table.csv#L182
        buff.put((byte) 0x13);
        buff.put((byte) 0x00);
        buff.put(Arrays.copyOfRange(privateKey, 0, privateKey.length));
        var unsupportedTypeMultibaseValue = "z" + Base58.encode(buff.array());
        assertThrowsExactly(IllegalArgumentException.class, () -> Ed25519Utils.decodeMultibase(unsupportedTypeMultibaseValue));
    }
}
