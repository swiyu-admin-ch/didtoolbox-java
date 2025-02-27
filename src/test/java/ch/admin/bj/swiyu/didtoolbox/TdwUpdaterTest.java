package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didresolver.Did;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TdwUpdaterTest {

    final private static VerificationMethodKeyProvider VERIFICATION_METHOD_KEY_PROVIDERS;

    static {
        try {
            //VERIFICATION_METHOD_KEY_PROVIDERS = List.of(new Ed25519VerificationMethodKeyProviderImpl(new File("src/test/data/private.pem"), new File("src/test/data/public.pem")));
            VERIFICATION_METHOD_KEY_PROVIDERS = new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias");
        } catch (Exception intolerable) {
            throw new RuntimeException(intolerable);
        }
    }

    private static void assertDidLogEntry(String didLogEntry) {

        assertNotNull(didLogEntry);
        assertTrue(JsonParser.parseString(didLogEntry).isJsonArray());
        JsonArray jsonArray = JsonParser.parseString(didLogEntry).getAsJsonArray();

        assertTrue(jsonArray.get(2).isJsonObject());
        var params = jsonArray.get(2).getAsJsonObject();
        //assertTrue(params.has("scid"));
        //assertTrue(params.has("updateKeys"));

        assertTrue(jsonArray.get(3).isJsonObject());
        assertTrue(jsonArray.get(3).getAsJsonObject().has("value"));
        var didDoc = jsonArray.get(3).getAsJsonObject().get("value").getAsJsonObject();
        assertTrue(didDoc.has("id"));
        assertTrue(didDoc.has("authentication"));
        assertTrue(didDoc.has("assertionMethod"));
        assertTrue(didDoc.has("verificationMethod"));
        assertTrue(didDoc.get("verificationMethod").isJsonArray());

        var proofs = jsonArray.get(4);
        assertTrue(proofs.isJsonArray());
        assertFalse(proofs.getAsJsonArray().isEmpty());
        var proof = proofs.getAsJsonArray().get(0);
        assertTrue(proof.isJsonObject());
        assertTrue(proof.getAsJsonObject().has("proofValue"));
    }

    private static String buildInitialDidLogEntry() {
        try {
            return TdwCreator.builder()
                    .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDERS)
                    .assertionMethodKeys(Map.of("my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01")))
                    .authenticationKeys(Map.of("my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01")))
                    .build()
                    .create(URL.of(new URI("https://127.0.0.1:54858"), null), ZonedDateTime.parse("2012-12-12T12:12:12Z"));
        } catch (Exception intolerable) {
            throw new RuntimeException(intolerable);
        }
    }

    @Test
    void testThrowsUpdateKeyMismatchException() {

        assertThrowsExactly(TdwUpdaterException.class, () -> {

            TdwUpdater.builder()
                    //.verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl("z6Mkg8QqetWTbAuxYN8oAY8N4bXg8UErkRHQhytByfmpdEr4", "z6Mkwf4PgXLq8sRfucTggtZXmigKZP7gQhFamk3XHGV54QvF"))
                    .build()
                    .update(buildInitialDidLogEntry()); // MUT
        });
    }

    @Test
    void testMultipleUpdates() {

        var initialDidLogEntry = buildInitialDidLogEntry();

        String nextLogEntry = null;
        StringBuilder updatedDidLog;
        try {

            // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
            updatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());
            for (int i = 2; i < 5; i++) { // update DID log by adding several new entries

                nextLogEntry = TdwUpdater.builder()
                        .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDERS)
                        .assertionMethodKeys(Map.of("my-assert-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-0" + i)))
                        .authenticationKeys(Map.of("my-auth-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-0" + i)))
                        .build()
                        // The versionTime for each log entry MUST be greater than the previous entry’s time.
                        // The versionTime of the last entry MUST be earlier than the current time.
                        .update(updatedDidLog.toString(), ZonedDateTime.parse("2012-12-1" + i + "T12:12:12Z")); // MUT;

                new StringBuilder(updatedDidLog.toString().trim()).append(System.lineSeparator()).append(nextLogEntry);
            }

            new Did(DidLogMetaPeeker.peek(initialDidLogEntry).didDocId).resolve(updatedDidLog.toString()); // the ultimate test

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(nextLogEntry);
    }
}
