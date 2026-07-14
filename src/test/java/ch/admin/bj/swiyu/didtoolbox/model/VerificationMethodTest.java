package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.eid.did_sidekicks.Ed25519SigningKey;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;


import java.io.*;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;

import static org.junit.jupiter.api.Assertions.*;

class VerificationMethodTest {

    @Test
    void verificationMethodOfJWK_withValidEcP256_returnVerificationMethod() throws VerificationMethodException {
        var jwk = """
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "WqLccrJ0NOQwVgFLP4cHCtEfR2M_SNguTsx9US5Ui7o",
                "y": "nhBUhaovZ6aw2tFeT25b1NFE96wYpY4z6WO5etAHfTw",
                "kid": "assert-key-01"
            }
            """;
        var method = VerificationMethod.of("fragment", "JsonWebKey2020", jwk);
        assertEquals("JsonWebKey2020", method.getType());
        assertEquals("fragment", method.getIdFragment());
        method.getVerificationMaterial().getPublicKeyJwk();
    }

    @Test
    void verificationMethodOfJWK_withValidEdDSA25519_returnsVerificationMethod() throws VerificationMethodException, JOSEException {
        var jwk = Ed25519SigningKey.Companion.generate().getVerifyingKey().toJwk();
        var method = VerificationMethod.of("fragment", "JsonWebKey2020", jwk);
        assertEquals("fragment", method.getIdFragment());
        method.getVerificationMaterial().getPublicKeyJwk();
    }

    @Test
    void verificationMethodOfJWK_withInvalidJWK_throwsError() {
        // empty json
        var emptyJwk = "{}";
        assertThrowsExactly(VerificationMethodException.class, () -> VerificationMethod.of("fragment", emptyJwk));

        // jwk with missing fields
        var incompleteJwk = "{\"kty\":\"EC\"}";
        assertThrowsExactly(VerificationMethodException.class, () -> VerificationMethod.of("fragment", incompleteJwk));
    }

    @Test
    void verificationMethodOfEcPublicKey_withValidKey_returnsVerificationMethod() throws NoSuchAlgorithmException {
        var keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        var key = (ECPublicKey)keyPair.getPublic();
        assertDoesNotThrow(() -> VerificationMethod.of("fragment", key));
    }

    @Test
    void verificationMethodOfPath_withEcP256Pem_returnsVerificationMethod() {
        var path = Path.of("src/test/data/assert-key-01.pub");
        assertDoesNotThrow(() -> VerificationMethod.of("fragment", path));
    }

    @Test
    void verificationMethodOfPath_withEdDSAPem_returnsVerificationMethod() {
        var path = Path.of("src/test/data/public.pem");
        assertDoesNotThrow(() -> VerificationMethod.of("fragment", path));
    }

    @Test
    void verificationMethOfPath_withNonPemfile_throwsError(@TempDir Path tempdir) throws FileNotFoundException {
        var file = new File(tempdir.toString(), "test.txt");
        try (var out = new PrintWriter(file)) {
            out.write("Foo");
        }

        var ex = assertThrowsExactly(IllegalArgumentException.class, () -> VerificationMethod.of("fragment", file.toPath()));
        assertTrue(ex.getMessage().contains("no PEM-encoded public key"));
    }
}
