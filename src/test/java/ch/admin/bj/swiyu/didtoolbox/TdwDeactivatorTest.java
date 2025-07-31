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
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class TdwDeactivatorTest {

    final private static String ISO_DATE_TIME;
    // final private static VerificationMethodKeyProvider VERIFICATION_METHOD_KEY_PROVIDER;
    final private static VerificationMethodKeyProvider VERIFICATION_METHOD_KEY_PROVIDER_JKS;
    final private static VerificationMethodKeyProvider EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER;
    final private static Map<String, String> ASSERTION_METHOD_KEYS;
    final private static Map<String, String> AUTHENTICATION_METHOD_KEYS;

    private static Collection<Object[]> keys() {
        return Arrays.asList(new String[][]{
                /*
                All lines in the private/public matrix were generated using openssl command by running the following script:

                openssl genpkey -algorithm ed25519 -out private.pem
                openssl pkey -inform pem -in private.pem -outform der -out private.der
                cat private.pem | openssl pkey -pubout -outform der -out public.der
                cat private.pem | openssl pkey -pubout -out public.pem
                secret_key_multibase=z$(echo ed01$(xxd -plain -cols 32 -s -32 private.der) | xxd -r -p | bs58)
                public_key_multibase=z$(echo ed01$(xxd -plain -cols 32 -s -32 public.der)  | xxd -r -p | bs58)
                echo "{\"${secret_key_multibase}\", \"${public_key_multibase}\", \"\"\"\n$(cat public.pem)\n\"\"\"}"
                 */
                {"z6MkmwdD6L2F3nZPFDmE5VwfBctqz3iRK3sufLQD7KeqeRmn", "z6Mkk3HuYK5Vah4BjBgHYZtbFzGHufw9TWDgBcXeEtjJEesW", """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAUwJJXsOciz7/TGdT2Osy0nOCqEL0oO67m0P3elFU9D0=
-----END PUBLIC KEY-----
"""},
                {"z6Mks1E1R9Ec3sQpFAe848dHuniKvgVRibSUoBGgk8QFgdeK", "z6MkfsYSSNJ3vWFceenzLfASHMcYk7e3dEza6vz1RZcyRfcR", """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAFRQpul8Rf/bxGK2ku4Loo8i7O1H/bvE7+U6RrQahOX4=
-----END PUBLIC KEY-----
"""},
        });
    }

    static {

        ISO_DATE_TIME = "2012-12-12T12:12:12Z";

        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-0
        EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER = new UnsafeEd25519VerificationMethodKeyProviderImpl(
                "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq",
                "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2");

        try {
            /*
            VERIFICATION_METHOD_KEY_PROVIDER = new Ed25519VerificationMethodKeyProviderImpl(
                    new File("src/test/data/private.pem"),
                    new File("src/test/data/public.pem"));
             */
            // Total 3 (PrivateKeyEntry) entries available in the JKS: myalias/myalias2/myalias3
            VERIFICATION_METHOD_KEY_PROVIDER_JKS = new Ed25519VerificationMethodKeyProviderImpl(
                    new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias", "changeit");

            ASSERTION_METHOD_KEYS = Map.of("my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01"));
            AUTHENTICATION_METHOD_KEYS = Map.of("my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01"));
        } catch (Exception intolerable) {
            throw new RuntimeException(intolerable);
        }
    }

    private static void assertDeactivatedDidLogEntry(String didLogEntry) {

        assertNotNull(didLogEntry);
        assertTrue(JsonParser.parseString(didLogEntry).isJsonArray());
        JsonArray jsonArray = JsonParser.parseString(didLogEntry).getAsJsonArray();

        assertTrue(jsonArray.get(2).isJsonObject());
        var params = jsonArray.get(2).getAsJsonObject();
        assertEquals(2, params.size()); // only "deactivated" (true) and optionally "updateKeys" (empty) expected
        assertTrue(params.has("deactivated")); // essential
        assertTrue(params.get("deactivated").getAsBoolean()); // essential
        assertTrue(params.has("updateKeys"));
        assertTrue(params.get("updateKeys").isJsonArray());

        assertTrue(jsonArray.get(3).isJsonObject());
        assertTrue(jsonArray.get(3).getAsJsonObject().has("value"));
        var didDoc = jsonArray.get(3).getAsJsonObject().get("value").getAsJsonObject();
        assertEquals(2, didDoc.size()); // no other than "id" and "context"
        assertTrue(didDoc.has("id"));
        assertTrue(didDoc.has("@context"));

        var proofs = jsonArray.get(4);
        assertTrue(proofs.isJsonArray());
        assertFalse(proofs.getAsJsonArray().isEmpty());
        var proof = proofs.getAsJsonArray().get(0);
        assertTrue(proof.isJsonObject());
        assertTrue(proof.getAsJsonObject().has("proofValue"));
    }

    /**
     * Also features an updateKey matching {@link #VERIFICATION_METHOD_KEY_PROVIDER_JKS}.
     *
     * @param verificationMethodKeyProvider
     * @return
     */
    private static String buildInitialDidLogEntry(VerificationMethodKeyProvider verificationMethodKeyProvider) {
        try {
            return TdwCreator.builder()
                    .verificationMethodKeyProvider(verificationMethodKeyProvider)
                    .assertionMethodKeys(ASSERTION_METHOD_KEYS)
                    .authenticationKeys(AUTHENTICATION_METHOD_KEYS)
                    .updateKeys(Set.of(new File("src/test/data/public.pem"))) // to be able to use VERIFICATION_METHOD_KEY_PROVIDER while updating
                    .build()
                    .create(URL.of(new URI("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085"), null), ZonedDateTime.parse(ISO_DATE_TIME));
        } catch (Exception simplyIntolerable) {
            throw new RuntimeException(simplyIntolerable);
        }
    }

    @Test
    void testDeactivateThrowsDeactivationKeyMismatchTdwDeactivatorException() {

        var exc = assertThrowsExactly(TdwDeactivatorException.class, () -> {
            TdwDeactivator.builder()
                    // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .deactivate(buildInitialDidLogEntry(VERIFICATION_METHOD_KEY_PROVIDER_JKS)); // MUT
        });
        assertEquals("Deactivation key mismatch", exc.getMessage());

        exc = assertThrowsExactly(TdwDeactivatorException.class, () -> {
            TdwDeactivator.builder()
                    .verificationMethodKeyProvider(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER) // using another verification key provider...
                    .build()
                    .deactivate(buildInitialDidLogEntry(VERIFICATION_METHOD_KEY_PROVIDER_JKS)); // MUT
        });
        assertEquals("Deactivation key mismatch", exc.getMessage());
    }

    @Test
    void testDeactivateThrowsDateTimeInThePastTdwDeactivatorException() {

        var exc = assertThrowsExactly(TdwDeactivatorException.class, () -> {
            TdwDeactivator.builder()
                    .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS)
                    .build()
                    .deactivate( // MUT
                            buildInitialDidLogEntry(VERIFICATION_METHOD_KEY_PROVIDER_JKS),
                            ZonedDateTime.parse(ISO_DATE_TIME).minusMinutes(1)); // In the past!
        });
        assertEquals("The versionTime of the last entry MUST be earlier than the current time", exc.getMessage());
    }

    @Test
    void testDeactivateWithKeyChangeUsingExistingUpdateKey() {

        // Also features an updateKey matching VERIFICATION_METHOD_KEY_PROVIDER
        var initialDidLogEntry = buildInitialDidLogEntry(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(TdwDeactivator.builder()
                    //.verificationMethodKeyProvider(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER)
                    .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS) // using a whole another verification key provider
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivate(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        assertDeactivatedDidLogEntry(nextLogEntry.get());

        deactivatedDidLog.append(nextLogEntry.get()).append(System.lineSeparator());

        var finalUpdatedDidLog = deactivatedDidLog.toString().trim(); // trimming due to a closing line separator

        //System.out.println(finalUpdatedDidLog); // checkpoint

        assertTrue("""
                ["1-QmQqae3Qu8aaeTSCTvErgGz8du3XvuZMrTwPiQfBkjZHuZ","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmSWR3nK8TG6bcymMqtHGihkvtisEz4nMh7qcNEwWp4b8K","updateKeys":["z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmSWR3nK8TG6bcymMqtHGihkvtisEz4nMh7qcNEwWp4b8K:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmSWR3nK8TG6bcymMqtHGihkvtisEz4nMh7qcNEwWp4b8K:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:tdw:QmSWR3nK8TG6bcymMqtHGihkvtisEz4nMh7qcNEwWp4b8K:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmSWR3nK8TG6bcymMqtHGihkvtisEz4nMh7qcNEwWp4b8K:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmSWR3nK8TG6bcymMqtHGihkvtisEz4nMh7qcNEwWp4b8K:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","proofPurpose":"authentication","challenge":"1-QmQqae3Qu8aaeTSCTvErgGz8du3XvuZMrTwPiQfBkjZHuZ","proofValue":"z5XZ7aHfrX4mCT8Epze7hVQAFaDDVWMwvbjz3LLq1c4QiPb7hVpveosoVyL7oD7EE1JsAkdvyjsXYc3kuChJf6UXm"}]]
                ["2-QmXLH8ripBZxLnmhr4tBjSw1yKVmmU4r4gmU96rGoXzytN","2012-12-12T12:12:13Z",{"deactivated":true,"updateKeys":[]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmSWR3nK8TG6bcymMqtHGihkvtisEz4nMh7qcNEwWp4b8K:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:13Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"2-QmXLH8ripBZxLnmhr4tBjSw1yKVmmU4r4gmU96rGoXzytN","proofValue":"zNqkHY1YKuAo6Mb6EfZVo8wGipVaTZD7ShWLJL6uZ6GQknaEE6iixNC167KyC26Kuu1Z6fcwkitqAqo45EF42Hij"}]]
                """.contains(finalUpdatedDidLog));

        assertDoesNotThrow(() -> {
            assertEquals(2, DidLogMetaPeeker.peek(finalUpdatedDidLog).lastVersionNumber); // there should be another entry i.e. one more
            new Did(DidLogMetaPeeker.peek(initialDidLogEntry).didDocId).resolve(finalUpdatedDidLog); // the ultimate test
        });
    }

    @Test
    void testUpdateAlreadyDeactivatedThrowsTdwUpdaterException() {

        // Also features an updateKey matching VERIFICATION_METHOD_KEY_PROVIDER
        var initialDidLogEntry = buildInitialDidLogEntry(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(TdwDeactivator.builder()
                    .verificationMethodKeyProvider(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER)
                    //.verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS) // using a whole another verification key provider
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivate(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        assertDeactivatedDidLogEntry(nextLogEntry.get());

        // Try updating the DID log
        var updaterExc = assertThrowsExactly(TdwUpdaterException.class, () -> {
            TdwUpdater.builder()
                    .verificationMethodKeyProvider(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER)
                    .build()
                    .update(new StringBuilder(initialDidLogEntry).append(System.lineSeparator()).append(nextLogEntry.get()).toString(),
                            // The versionTime for each log entry MUST be greater than the previous entry’s time.
                            // The versionTime of the last entry MUST be earlier than the current time.
                            ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(2));
        });
        assertEquals("DID already deactivated", updaterExc.getMessage());
    }

    @Test
    void testDeactivateAlreadyDeactivatedThrowsTdwDeactivatorException() {

        // Also features an updateKey matching VERIFICATION_METHOD_KEY_PROVIDER
        var initialDidLogEntry = buildInitialDidLogEntry(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(TdwDeactivator.builder()
                    .verificationMethodKeyProvider(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER)
                    //.verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS) // using a whole another verification key provider
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivate(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        assertDeactivatedDidLogEntry(nextLogEntry.get());

        deactivatedDidLog.append(nextLogEntry.get()).append(System.lineSeparator());

        // trying to deactivate it again should fail
        var exc = assertThrowsExactly(TdwDeactivatorException.class, () -> {
            nextLogEntry.set(TdwDeactivator.builder()
                    //.verificationMethodKeyProvider(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER) // is actually irrelevant for the test case
                    //.verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS) // using a whole another verification key provider
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivate(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(2))); // MUT
        });
        assertEquals("DID already deactivated", exc.getMessage());
    }
}
