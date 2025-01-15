package ch.admin.bj.swiyu.didtoolbox;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

class JwkUtilsTest {

    @Test
    void testGeneratePublicEC256() {
        try {
            String json = JwkUtils.generatePublicEC256("auth-key-01", null);
            assertNotNull(json);
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGeneratePublicEC256WithOutput() {
        try {
            File tempFile = File.createTempFile("myprivatekey", "");
            tempFile.deleteOnExit();
            String json = JwkUtils.generatePublicEC256("auth-key-01", tempFile);
            assertNotNull(json);
            assertNotEquals(0, Files.size(tempFile.toPath()));
            assertNotEquals(0, Files.size(new File(tempFile.getPath() + ".json").toPath()));
            assertNotEquals(0, Files.size(new File(tempFile.getPath() + ".pub").toPath()));
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