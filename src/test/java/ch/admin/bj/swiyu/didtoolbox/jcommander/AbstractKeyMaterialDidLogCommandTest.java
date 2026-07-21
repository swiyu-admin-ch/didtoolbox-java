package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.model.CryptographicAlgorithm;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AbstractKeyMaterialDidLogCommandTest {
    private final String jwk = """
    {
        "kty": "EC",
        "crv": "P-256",
        "x": "ZcDtTSv1dP94JR9zTqFSO4hRPPByCQ0ctYGZdHyeHws",
        "y": "lOlpaJZbQDyJFRCBOEMQLzPeoG02pa3G5Ux5tIYMXHo"
    }
    """;

    // Extends AbstractKeyMaterialDidLogCommand to test that class
    private static class Command extends AbstractKeyMaterialDidLogCommand {}

    @Test
    void getAssertionMethods_noMethodsProvided_generateKeys(@TempDir Path tmpDir) {
        var command = new Command();
        assertDoesNotThrow(() -> {
            var keys = command.getAssertionMethods(tmpDir);
            assertEquals(1, keys.size());
            var method = keys.stream().findFirst();
            assertTrue(method.isPresent());
            assertEquals("assert-key-01", method.get().getIdFragment());
        });
        assertEquals(2, tmpDir.toFile().listFiles().length);
    }

    @Test
    void getAssertionMethods_typeP256_generateKeys(@TempDir Path tmpDir) {
        var command = new Command();
        command.cryptoAlgorithm = CryptographicAlgorithm.P256;

        assertDoesNotThrow(() -> {
            var keys = command.getAssertionMethods(tmpDir);
            assertEquals(1, keys.size());
            var method = keys.stream().findFirst();
            assertTrue(method.isPresent());
            assertEquals("assert-key-01", method.get().getIdFragment());
        });
        assertEquals(2, tmpDir.toFile().listFiles().length);

        assertDoesNotThrow(() -> {
            var jwk = JwkUtils.loadECPublicJWKasJSON(new File(tmpDir.toString(), "assert-key-01.pub"), "foo");
            var jsonJwk = JsonParser.parseString(jwk).getAsJsonObject();
            var crv = jsonJwk.get("crv");
            assertEquals("P-256", crv.getAsString());
        });
    }

    @Test
    void getAssertionMethods_typeEd25519_generateKeys(@TempDir Path tmpDir) {
        var command = new Command();
        command.cryptoAlgorithm = CryptographicAlgorithm.ED25519;

        assertDoesNotThrow(() -> {
            var keys = command.getAssertionMethods(tmpDir);
            assertEquals(1, keys.size());
            var method = keys.stream().findFirst();
            assertTrue(method.isPresent());
            assertEquals("assert-key-01", method.get().getIdFragment());
        });
        assertEquals(2, tmpDir.toFile().listFiles().length);

        assertDoesNotThrow(() -> {
            var jwk = JwkUtils.loadECPublicJWKasJSON(new File(tmpDir.toString(), "assert-key-01.pub"), "foo");
            var jsonJwk = JsonParser.parseString(jwk).getAsJsonObject();
            var crv = jsonJwk.get("crv");
            assertEquals("Ed25519", crv.getAsString());
        });
    }

    @Test
    void getAssertionMethods_withMethods_doesNotGenerateKeys(@TempDir Path tmpDir) {
        var command =  new Command();
        command.assertionMethodKeys = Set.of(new VerificationMethodParameters("foo", jwk));
        assertDoesNotThrow(() -> {
            var keys = command.getAssertionMethods(tmpDir);
            assertEquals(1, keys.size());
            var method = keys.stream().findFirst();
            assertTrue(method.isPresent());
            assertEquals("foo", method.get().getIdFragment());
        });
        // directory should stay empty
        assertEquals(0, tmpDir.toFile().listFiles().length);
    }

    @Test
    void getAssertionMethods_withoutMethodsAndExistingPublicKeyFileNoOverwrite_throwsException(@TempDir Path tmpDir) throws IOException {
        var publicFile = new File(tmpDir.toString(), "assert-key-01.pub");
        publicFile.createNewFile();

        var command = new Command();
        assertThrowsExactly(IOException.class, () -> command.getAssertionMethods(tmpDir));
    }

    @Test
    void getAssertionMethods_withoutMethodsAndExistingPrivateKeyFileNoOverwrite_throwsException(@TempDir Path tmpDir) throws IOException {
        var privateFile = new File(tmpDir.toString(), "assert-key-01");
        privateFile.createNewFile();

        var command = new Command();
        assertThrowsExactly(IOException.class, () -> command.getAssertionMethods(tmpDir));
    }

    @Test
    void getAuthentications_noMethodsProvided_generateKeys(@TempDir Path tmpDir) {
        var command = new Command();
        assertDoesNotThrow(() -> {
            var keys = command.getAuthentications(tmpDir);
            assertEquals(1, keys.size());
            var method = keys.stream().findFirst();
            assertTrue(method.isPresent());
            assertEquals("auth-key-01", method.get().getIdFragment());
        });
        assertEquals(2, tmpDir.toFile().listFiles().length);
    }

    @Test
    void getAuthentications_withMethods_doesNotGenerateKeys(@TempDir Path tmpDir) {
        var command =  new Command();
        command.authenticationKeys = Set.of(new VerificationMethodParameters("foo", jwk));
        assertDoesNotThrow(() -> {
            var keys = command.getAuthentications(tmpDir);
            assertEquals(1, keys.size());
            var method = keys.stream().findFirst();
            assertTrue(method.isPresent());
            assertEquals("foo", method.get().getIdFragment());
        });
        // directory should stay empty
        assertEquals(0, tmpDir.toFile().listFiles().length);
    }

    @Test
    void getAuthentications_withoutMethodsAndExistingPublicKeyFileNoOverwrite_throwsException(@TempDir Path tmpDir) throws IOException {
        var publicFile = new File(tmpDir.toString(), "auth-key-01.pub");
        publicFile.createNewFile();

        var command = new Command();
        assertThrowsExactly(IOException.class, () -> command.getAuthentications(tmpDir));
    }

    @Test
    void getAuthentications_withoutMethodsAndExistingPrivateKeyFileNoOverwrite_throwsException(@TempDir Path tmpDir) throws IOException {
        var privateFile = new File(tmpDir.toString(), "auth-key-01");
        privateFile.createNewFile();

        var command = new Command();
        assertThrowsExactly(IOException.class, () -> command.getAuthentications(tmpDir));
    }

}
