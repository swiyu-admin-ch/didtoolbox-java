package ch.admin.bj.swiyu.didtoolbox.model;

import com.google.gson.JsonParser;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import org.junit.jupiter.api.Test;

import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;

import static org.junit.jupiter.api.Assertions.*;

class VerificationMaterialTest {

    private void assertKid(String expectedKid, VerificationMaterial material) {
        var jwk = material.getPublicKeyJwk();
        var json = JsonParser.parseString(jwk).getAsJsonObject();
        var kid = json.get("kid");
        assertNotNull(kid);
        assertTrue(kid.isJsonPrimitive());
        assertEquals(expectedKid, kid.getAsString());
    }

    @Test
    void of_validEcPublicKey_returnsVerificationMaterial() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator;
        keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        var verificationMaterial = VerificationMaterial.of("example_kid",(ECPublicKey) keyPair.getPublic());
        assertKid("example_kid", verificationMaterial);

    }

    @Test
    void of_pathToP256PemFile_returnsVerificationMaterial() {
        var path = Path.of("src/test/data/assert-key-01.pub");
        assertDoesNotThrow(() -> {
            var verificationMaterial = VerificationMaterial.of("example_kid", path);
            assertKid("example_kid", verificationMaterial);
        });
    }

    @Test
    void of_pathToEd25519PemFile_returnsVerificationMaterial() {
        var path = Path.of("src/test/data/public.pem");
        assertDoesNotThrow(() -> {
            var verificationMaterial = VerificationMaterial.of("example_kid", path);
            assertKid("example_kid", verificationMaterial);
        });
    }

    @Test
    void of_pathToUnsupportedPemFile_throwsIllegalArgumentException() {
        var path = Path.of("src/test/data/rsa");
        assertThrowsExactly(IllegalArgumentException.class, () -> VerificationMaterial.of("example_kid", path));
    }

    @Test
    void of_pathToMissingFile_throwsError() {
        var path = Path.of("thisFileDoesNotExist.pem");
        assertThrowsExactly(NoSuchFileException.class, () -> VerificationMaterial.of("example_kid", path));
    }

    @Test
    void of_pathToWrongFile_throwsError() {
        var path = Path.of("README.md");
        assertThrowsExactly(IllegalArgumentException.class, () -> VerificationMaterial.of("example_kid", path));
    }

    @Test
    void of_ecP256PemString_returnsVerificationMaterial() {
        String ecP256Pem = """
           -----BEGIN PUBLIC KEY-----
           MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwdET0dp6vq59s1yyVh/XXyIPPU9C
           o7PlcTPMRRXx85Z5OEL3416036hcDlZTQOfR553t+Ae2xezYTeZTzakD2Q==
           -----END PUBLIC KEY-----
           """;
        assertDoesNotThrow(() -> {
            var verificationMaterial = VerificationMaterial.of("example_kid", ecP256Pem);
            assertKid("example_kid", verificationMaterial);
        });
    }

    @Test
    void of_ed25519PemString_returnsVerificationMaterial() {
        String ed25519 = """
          -----BEGIN PUBLIC KEY-----
          MCowBQYDK2VwAyEA8ETLwQBKgk9fM2V0tQV5AdjrMvetLrgj5C+FOmYGTJg=
          -----END PUBLIC KEY-----
          """;
        assertDoesNotThrow(() -> {
            var verificationMaterial = VerificationMaterial.of("example_kid", ed25519);
            assertKid("example_kid", verificationMaterial);
        });
    }

    @Test
    void of_invalidPemString_throwsError() {
        String invalidPem = """
          Not a Pem
          """;
        assertThrowsExactly(IllegalArgumentException.class, () -> VerificationMaterial.of("example_kid", invalidPem));
    }
}
