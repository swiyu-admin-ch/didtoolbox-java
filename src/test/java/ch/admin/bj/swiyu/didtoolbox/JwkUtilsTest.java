package ch.admin.bj.swiyu.didtoolbox;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

class JwkUtilsTest {

    @Test
    void testGenerateEd25519() { //throws JOSEException {
        try {
            String json = JwkUtils.generateEd25519("auth-key-01", null);
            assertNotNull(json);
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testGenerateEd25519WithOutput() { //throws JOSEException {
        try {
            File tempFile = File.createTempFile("myprivatekey", "");
            tempFile.deleteOnExit();
            String json = JwkUtils.generateEd25519("auth-key-01", tempFile);
            assertNotNull(json);
            assertNotEquals(0, Files.size(tempFile.toPath()));
            assertNotEquals(0, Files.size(new File(tempFile.getPath() + ".json").toPath()));
            assertNotEquals(0, Files.size(new File(tempFile.getPath() + ".pub").toPath()));
        } catch (Exception e) {
            fail(e);
        }
    }

    /*
    @Test
    void testLoadKeyStoreFile() { //throws JOSEException {
        try {
            var jwk = JwkUtils.loadKeyStore("src/test/data/mykeystore.jks", "changeit", "myalias"); // MUT
            assertNotNull(jwk);
        } catch (Exception e) {
            fail(e);
        }
    }
     */

    @Test
    void testParseFile() { //throws JOSEException {
        try {
            var jwk = JwkUtils.load(new File("src/test/data/myjsonwebkeys.json"), "my-auth-key-01"); // MUT
            assertNotNull(jwk);
            jwk = JwkUtils.load(new File("src/test/data/myjsonwebkeys.json"), "my-assert-key-01"); // MUT
            assertNotNull(jwk);
        } catch (Exception e) {
            fail(e);
        }
    }
}