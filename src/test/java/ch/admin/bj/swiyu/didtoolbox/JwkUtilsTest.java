package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

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
            assertGeneratePublicEC256(JwkUtils.generatePublicEC256("auth-key-01", null), null); // MUT
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGeneratePublicEC256WithOutput() {
        try {
            File tempFile = File.createTempFile("myprivatekey", "");
            tempFile.deleteOnExit();

            var kid = "auth-key-01";
            assertGeneratePublicEC256(JwkUtils.generatePublicEC256(kid, tempFile), kid); // MUT

            // Verification of the exported PEM files
            assertNotEquals(0, Files.size(tempFile.toPath()));
            assertNotEquals(0, Files.size(new File(tempFile.getPath() + ".pub").toPath()));
            JwkUtils.ecPemSanityCheck(tempFile, new File(tempFile.getPath() + ".pub"));

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
}
