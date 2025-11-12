package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all PMD warnings in this class
@SuppressWarnings({"PMD"})
class JwkUtilsTest {

    private static void assertGeneratePublicEC256(String json, String kid) {
        assertNotNull(json);
        var publicJwkJsonObject = JsonParser.parseString(json).getAsJsonObject();
        assertTrue(publicJwkJsonObject.has("kty"));
        assertEquals("EC", publicJwkJsonObject.get("kty").getAsString());
        assertTrue(publicJwkJsonObject.has("crv"));
        assertEquals("P-256", publicJwkJsonObject.get("crv").getAsString());
        if (kid != null) {
            assertTrue(publicJwkJsonObject.has("kid"));
            assertEquals(kid, publicJwkJsonObject.get("kid").getAsString());
        }

        assertFalse(publicJwkJsonObject.has("d")); // what makes it public and not private
    }

    @Test
    void testGeneratePublicEC256() {
        try {
            // No PEM files are exported here
            assertGeneratePublicEC256(JwkUtils.generatePublicEC256("auth-key-01", null, false), null); // MUT
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGeneratePublicEC256WithOutputOverwriteExisting() {
        try {
            var tempFile = File.createTempFile("myprivatekey", "");
            // Exists at the moment of key generation, and should therefore be overwritten if forceOverwritten == true
            tempFile.deleteOnExit();

            var kid = "auth-key-01";
            assertGeneratePublicEC256(JwkUtils.generatePublicEC256(kid, tempFile, true), kid); // MUT

            // Verification of the exported PEM files
            assertNotEquals(0, Files.size(tempFile.toPath()));
            var pubTempFile = new File(tempFile.getPath() + ".pub");
            assertNotEquals(0, Files.size(pubTempFile.toPath()));
            JwkUtils.ecPemSanityCheck(tempFile, pubTempFile);
            pubTempFile.deleteOnExit(); // clean it up

        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGeneratePublicEC256WithOutputNoOverwriteExistingThrowsException() {
        File tempFile = null;
        try {
            tempFile = File.createTempFile("myprivatekey", "");
            // Exists at the moment of key generation, and should NOT be overwritten if forceOverwritten == false
            tempFile.deleteOnExit();
        } catch (Exception e) {
            fail(e);
        }

        File finalTempFile = tempFile;
        var exc = assertThrowsExactly(IOException.class, () -> {
            // kid is irrelevant here
            JwkUtils.generatePublicEC256(null, finalTempFile, false); // MUT
        });
        assertTrue(exc.getMessage().contains("The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged"));

        try {
            // The temp file should remain empty
            assertEquals(0, Files.size(tempFile.toPath()));
            // And NO matching .pub file should be created
            var pubTempFile = new File(tempFile.getPath() + ".pub");
            assertFalse((pubTempFile.exists()));
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGeneratePublicEC256WithOutputOverwriteNonExisting() {
        File tempFile;
        File pubTempFile;
        try {
            tempFile = File.createTempFile("myprivatekey", "");
            // Delete it immediately, so it will NOT exist at the moment of key generation and should therefore be created regardless of forceOverwritten flag
            tempFile.deleteOnExit();

            var kid = "auth-key-01";
            assertGeneratePublicEC256(JwkUtils.generatePublicEC256(kid, tempFile, true), kid); // MUT

            // Verification of the exported PEM files
            assertNotEquals(0, Files.size(tempFile.toPath()));
            pubTempFile = new File(tempFile.getPath() + ".pub");
            assertNotEquals(0, Files.size(pubTempFile.toPath()));
            JwkUtils.ecPemSanityCheck(tempFile, pubTempFile);
            pubTempFile.deleteOnExit(); // clean it up

        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testLoadECPublicJWKasJSON() {
        try {
            var jwk = JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01"); // MUT
            assertNotNull(jwk);
            jwk = JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01"); // MUT
            assertNotNull(jwk);
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testLoadECPublicJWKasJSONThrowsIllegalArgumentException() {

        /* A "kid" featuring URIs "Reserved Characters" (incl. "Percent-Encoding") must fail:
        pct-encoded = "%" HEXDIG HEXDIG
        reserved    = gen-delims / sub-delims
        gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
        sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
         */
        var kids = new HashSet<>(Arrays.asList(
                "",
                "kid-contains-%-gen-delim",
                "kid-contains-:-gen-delim",
                "kid-contains-/-gen-delim",
                "kid-contains-?-gen-delim",
                "kid-contains-#-gen-delim",
                "kid-contains-[-gen-delim",
                "kid-contains-]-gen-delim",
                "kid-contains-@-gen-delim",
                "kid-contains-!-sub-delim",
                "kid-contains-$-sub-delim",
                "kid-contains-&-sub-delim",
                "kid-contains-'-sub-delim",
                "kid-contains-\"-sub-delim",
                "kid-contains-(-sub-delim",
                "kid-contains-)-sub-delim",
                "kid-contains-*-sub-delim",
                "kid-contains-+-sub-delim",
                "kid-contains-,-sub-delim",
                "kid-contains-;-sub-delim",
                "kid-contains-=-sub-delim"
        ));

        for (var kid : kids) {
            var ex = assertThrowsExactly(IllegalArgumentException.class, () -> {
                JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), kid); // MUT
            });
            assertTrue(ex.getMessage().contains("must be a regular case-sensitive string featuring no URIs reserved characters"));
        }
    }
}
