package ch.admin.bj.swiyu.didtoolbox;

import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

class JwkUtilsTest {

    @Test
    void generateEd25519() { //throws JOSEException {
        try {
            String json = JwkUtils.generateEd25519("auth-key-01");
            assertNotNull(json);
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