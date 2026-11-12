package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethod;
import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethodException;
import ch.admin.eid.did_sidekicks.Ed25519SigningKey;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;


import java.io.*;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;

import static org.junit.jupiter.api.Assertions.*;

class VerificationMethodTest {

    private void assertKid(String expectedKid, VerificationMethod method) {
        var jwk = method.getPublicKey();
        var json = JsonParser.parseString(jwk).getAsJsonObject();
        var kid = json.get("kid");
        assertNotNull(kid);
        assertTrue(kid.isJsonPrimitive());
        assertEquals(expectedKid, kid.getAsString());
    }

    @Test
    void of_validEcPublicKey_returnsVerificationMethod() throws NoSuchAlgorithmException, VerificationMethodException {
        KeyPairGenerator keyPairGenerator;
        keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        var verificationMethod = VerificationMethod.ofEcPublicKey("example_kid",(ECPublicKey) keyPair.getPublic());
        assertKid("example_kid", verificationMethod);

    }

    @Test
    void of_pathToP256PemFile_returnsVerificationMethod() {
        var path = Path.of("src/test/data/assert-key-01.pub");
        assertDoesNotThrow(() -> {
            var verificationMethod = VerificationMethod.ofPEMPath("example_kid", path);
            assertKid("example_kid", verificationMethod);
        });
    }

    @Test
    void of_pathToEd25519PemFile_returnsVerificationMethod() {
        var path = Path.of("src/test/data/public.pem");
        assertDoesNotThrow(() -> {
            var verificationMethod = VerificationMethod.ofPEMPath("example_kid", path);
            assertKid("example_kid", verificationMethod);
        });
    }

    @Test
    void of_pathToUnsupportedPemFile_throwsIllegalArgumentException() {
        var path = Path.of("src/test/data/rsa");
        assertThrowsExactly(IllegalArgumentException.class, () -> VerificationMethod.ofPEMPath("example_kid", path));
    }

    @Test
    void of_pathToMissingFile_throwsError() {
        var path = Path.of("thisFileDoesNotExist.pem");
        assertThrowsExactly(NoSuchFileException.class, () -> VerificationMethod.ofPEMPath("example_kid", path));
    }

    @Test
    void of_pathToWrongFile_throwsError() {
        var path = Path.of("README.md");
        assertThrowsExactly(IllegalArgumentException.class, () -> VerificationMethod.ofPEMPath("example_kid", path));
    }

    @Test
    void of_ecP256PemString_returnsVerificationMethod() {
        String ecP256Pem = """
           -----BEGIN PUBLIC KEY-----
           MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwdET0dp6vq59s1yyVh/XXyIPPU9C
           o7PlcTPMRRXx85Z5OEL3416036hcDlZTQOfR553t+Ae2xezYTeZTzakD2Q==
           -----END PUBLIC KEY-----
           """;
        assertDoesNotThrow(() -> {
            var verificationMethod = VerificationMethod.ofPEM("example_kid", ecP256Pem);
            assertKid("example_kid", verificationMethod);
        });
    }

    @Test
    void of_ed25519PemString_returnsVerificationMethod() {
        String ed25519 = """
          -----BEGIN PUBLIC KEY-----
          MCowBQYDK2VwAyEA8ETLwQBKgk9fM2V0tQV5AdjrMvetLrgj5C+FOmYGTJg=
          -----END PUBLIC KEY-----
          """;
        assertDoesNotThrow(() -> {
            var verificationMethod = VerificationMethod.ofPEM("example_kid", ed25519);
            assertKid("example_kid", verificationMethod);
        });
    }

    @Test
    void of_invalidPemString_throwsError() {
        String invalidPem = """
          Not a Pem
          """;
        assertThrowsExactly(IllegalArgumentException.class, () -> VerificationMethod.ofPEM("example_kid", invalidPem));
    }

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
        var method = VerificationMethod.ofJWK("fragment", jwk);
        assertEquals("JsonWebKey2020", method.getType());
        assertEquals("fragment", method.getIdFragment());
        method.getPublicKey();
    }

    @Test
    void verificationMethodOfJWK_withValidEdDSA25519_returnsVerificationMethod() throws VerificationMethodException, JOSEException {
        var jwk = Ed25519SigningKey.Companion.generate().getVerifyingKey().toJwk();
        var method = VerificationMethod.ofJWK("fragment", jwk);
        assertEquals("fragment", method.getIdFragment());
        method.getPublicKey();
    }

    @Test
    void verificationMethodOfJWK_withInvalidJWK_throwsError() {
        // empty json
        var emptyJwk = "{}";
        assertThrowsExactly(VerificationMethodException.class, () -> VerificationMethod.ofJWK("fragment", emptyJwk));

        // jwk with missing fields
        var incompleteJwk = "{\"kty\":\"EC\"}";
        assertThrowsExactly(VerificationMethodException.class, () -> VerificationMethod.ofJWK("fragment", incompleteJwk));
    }

    @Test
    void verificationMethodOfEcPublicKey_withValidKey_returnsVerificationMethod() throws NoSuchAlgorithmException {
        var keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        var key = (ECPublicKey)keyPair.getPublic();
        assertDoesNotThrow(() -> VerificationMethod.ofEcPublicKey("fragment", key));
    }

    @Test
    void verificationMethodOfPath_withEcP256Pem_returnsVerificationMethod() {
        var path = Path.of("src/test/data/assert-key-01.pub");
        assertDoesNotThrow(() -> VerificationMethod.ofPEMPath("fragment", path));
    }

    @Test
    void verificationMethodOfPath_withEdDSAPem_returnsVerificationMethod() {
        var path = Path.of("src/test/data/public.pem");
        assertDoesNotThrow(() -> VerificationMethod.ofPEMPath("fragment", path));
    }

    @Test
    void verificationMethodOfPath_withNonPemfile_throwsError(@TempDir Path tempdir) throws FileNotFoundException {
        var file = new File(tempdir.toString(), "test.txt");
        try (var out = new PrintWriter(file)) {
            out.write("Foo");
        }

        var ex = assertThrowsExactly(IllegalArgumentException.class, () -> VerificationMethod.ofPEMPath("fragment", file.toPath()));
        assertTrue(ex.getMessage().contains("no PEM-encoded public key"));
    }

}
