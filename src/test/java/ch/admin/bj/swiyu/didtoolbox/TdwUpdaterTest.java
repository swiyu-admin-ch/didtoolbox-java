package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didresolver.Did;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class TdwUpdaterTest {

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
                    .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new File("src/test/data/private.pem"), new File("src/test/data/public.pem")))
                    .assertionMethodKeys(Map.of("my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01")))
                    .authenticationKeys(Map.of("my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01")))
                    .build()
                    .create(URL.of(new URI("https://127.0.0.1:54858"), null), ZonedDateTime.parse("2012-12-12T12:12:12Z"));
        } catch (Exception intolerable) {
            throw new RuntimeException(intolerable);
        }
    }

    @Test
    public void testUpdateThrowsAuthKeyAlreadyExistsException() {

        assertThrowsExactly(IOException.class, () -> {

            var initialDidLogEntry = buildInitialDidLogEntry();
            var didTDW = DidLogMetaPeeker.peek(initialDidLogEntry).didDocId;

            TdwUpdater.builder()
                    //.verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new File("src/test/data/private.pem"), new File("src/test/data/public.pem")))
                    .authenticationKeys(Map.of(
                            "my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01") // exists already
                    ))
                    .build()
                    .update(didTDW, initialDidLogEntry); // MUT
        });
    }

    @Test
    public void testUpdateThrowsAssertionKeyAlreadyExistsException() {

        assertThrowsExactly(IOException.class, () -> {

            var initialDidLogEntry = buildInitialDidLogEntry();
            var didTDW = DidLogMetaPeeker.peek(initialDidLogEntry).didDocId;

            TdwUpdater.builder()
                    //.verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new File("src/test/data/private.pem"), new File("src/test/data/public.pem")))
                    .assertionMethodKeys(Map.of(
                            "my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01") // exists already
                    ))
                    .build()
                    .update(didTDW, initialDidLogEntry); // MUT
        });
    }

    @Test
    public void testThrowsUpdateKeyMismatchException() {

        assertThrowsExactly(IOException.class, () -> {

            var initialDidLogEntry = buildInitialDidLogEntry();
            var didTDW = DidLogMetaPeeker.peek(initialDidLogEntry).didDocId;

            TdwUpdater.builder()
                    //.verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl("z6Mkg8QqetWTbAuxYN8oAY8N4bXg8UErkRHQhytByfmpdEr4", "z6Mkwf4PgXLq8sRfucTggtZXmigKZP7gQhFamk3XHGV54QvF"))
                    .build()
                    .update(didTDW, initialDidLogEntry); // MUT
        });
    }

    @Test
    public void testMultipleUpdates() {

        var initialDidLogEntry = buildInitialDidLogEntry();

        String nextLogEntry = null;
        StringBuilder updatedDidLog;
        try {
            var didTDW = DidLogMetaPeeker.peek(initialDidLogEntry).didDocId;
            var verificationMethodKeyProvider1 = new Ed25519VerificationMethodKeyProviderImpl(new File("src/test/data/private.pem"), new File("src/test/data/public.pem"));

            updatedDidLog = new StringBuilder(initialDidLogEntry);
            for (int i = 2; i < 5; i++) { // update DID log by adding several new entries

                nextLogEntry = TdwUpdater.builder()
                        .verificationMethodKeyProvider(verificationMethodKeyProvider1)
                        .assertionMethodKeys(Map.of("my-assert-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-0" + i)))
                        .authenticationKeys(Map.of("my-auth-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-0" + i)))
                        .build()
                        .update(didTDW, updatedDidLog.toString(), ZonedDateTime.parse("2012-12-21T12:12:12Z")); // MUT;

                updatedDidLog.append(System.lineSeparator()).append(nextLogEntry);
            }

            new Did(didTDW).resolve(updatedDidLog.toString()); // ultimate test

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(nextLogEntry);
    }
}
