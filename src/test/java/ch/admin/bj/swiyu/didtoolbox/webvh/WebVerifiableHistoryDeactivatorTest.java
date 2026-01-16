package ch.admin.bj.swiyu.didtoolbox.webvh;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.model.NamedDidMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.model.WebVerifiableHistoryDidLogMetaPeeker;
import ch.admin.eid.didresolver.Did;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress PMD warnings in this (test) class
@SuppressWarnings({"PMD"})
class WebVerifiableHistoryDeactivatorTest extends AbstractUtilTestBase {

    private static void assertDeactivatedDidLogEntry(String didLogEntry) {

        assertNotNull(didLogEntry);
        assertTrue(JsonParser.parseString(didLogEntry).isJsonObject());
        var jsonObject = JsonParser.parseString(didLogEntry).getAsJsonObject();

        assertTrue(jsonObject.get("parameters").isJsonObject());
        assertFalse(jsonObject.get("parameters").isJsonNull());
        var params = jsonObject.get("parameters").getAsJsonObject();
        assertEquals(2, params.size()); // only "deactivated" (true) and optionally "updateKeys" (empty) expected
        assertTrue(params.has("deactivated")); // essential
        assertTrue(params.get("deactivated").getAsBoolean()); // essential
        assertTrue(params.has(NamedDidMethodParameters.UPDATE_KEYS));
        var updateKeys = params.get(NamedDidMethodParameters.UPDATE_KEYS);
        assertTrue(updateKeys.isJsonArray());
        assertTrue(updateKeys.getAsJsonArray().isEmpty());

        assertTrue(jsonObject.get("state").isJsonObject());
        var didDoc = jsonObject.get("state").getAsJsonObject();
        assertEquals(2, didDoc.size()); // no other than "id" and "context"
        assertTrue(didDoc.has("id"));
        assertTrue(didDoc.has("@context"));

        var proofs = jsonObject.get("proof");
        assertTrue(proofs.isJsonArray());
        assertFalse(proofs.getAsJsonArray().isEmpty());
        var proof = proofs.getAsJsonArray().get(0);
        assertTrue(proof.isJsonObject());
        assertTrue(proof.getAsJsonObject().has("proofValue"));
    }

    @Test
    void testDeactivateThrowsDeactivationKeyMismatchWebVerifiableHistoryDeactivatorException() {

        var exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            WebVerifiableHistoryDeactivator.builder()
                    // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .deactivateDidLog(buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS)); // MUT
        });
        assertEquals("Deactivation key mismatch", exc.getMessage());

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            WebVerifiableHistoryDeactivator.builder()
                    .verificationMethodKeyProvider(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .build()
                    .deactivateDidLog(buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS)); // MUT
        });
        assertEquals("Deactivation key mismatch", exc.getMessage());
    }

    @Test
    void testDeactivateThrowsDateTimeInThePastWebVerifiableHistoryDeactivatorException() {

        var exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            WebVerifiableHistoryDeactivator.builder()
                    .verificationMethodKeyProvider(TEST_CRYPTO_SUITE_JKS)
                    .build()
                    .deactivateDidLog( // MUT
                            buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS),
                            ZonedDateTime.parse(ISO_DATE_TIME).minusMinutes(1)); // In the past!
        });
        assertEquals("The versionTime of the last entry MUST be earlier than the current time", exc.getMessage());
    }

    @Test
    void testDeactivateWithKeyChangeUsingExistingUpdateKey() {

        // Also features an updateKey matching VERIFICATION_METHOD_KEY_PROVIDER
        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(WebVerifiableHistoryDeactivator.builder()
                    //.verificationMethodKeyProvider(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER)
                    .verificationMethodKeyProvider(TEST_CRYPTO_SUITE_JKS) // using a whole another verification key provider
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        assertDeactivatedDidLogEntry(nextLogEntry.get());

        deactivatedDidLog.append(nextLogEntry.get()).append(System.lineSeparator());

        var finalUpdatedDidLog = deactivatedDidLog.toString().trim(); // trimming due to a closing line separator

        //System.out.println(finalUpdatedDidLog); // checkpoint

        assertTrue("""
                {"versionId":"1-QmVvJn5X1Dsm6rtNhWCRawstNC2DLHHRnUmgfjioev43en","versionTime":"2012-12-12T12:12:12Z","parameters":{"method":"did:webvh:1.0","scid":"QmPLFTzZ7p5ekx2XkPRsC4Kn5xYWLVHEsG2jHvzZRqhorj","updateKeys":["z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmPLFTzZ7p5ekx2XkPRsC4Kn5xYWLVHEsG2jHvzZRqhorj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:webvh:QmPLFTzZ7p5ekx2XkPRsC4Kn5xYWLVHEsG2jHvzZRqhorj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:webvh:QmPLFTzZ7p5ekx2XkPRsC4Kn5xYWLVHEsG2jHvzZRqhorj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmPLFTzZ7p5ekx2XkPRsC4Kn5xYWLVHEsG2jHvzZRqhorj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:webvh:QmPLFTzZ7p5ekx2XkPRsC4Kn5xYWLVHEsG2jHvzZRqhorj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","proofPurpose":"assertionMethod","proofValue":"z5Rpe7yyrTpgfDvrye2aNSzJtgW96g7srgbWvseS5oBeveVkPTWZS4BVJv4QZjKXz8jA3w3bWMtGCVmDMHGJWiJ5h"}]}
                {"versionId":"2-QmdmUZujBrzuE6JZk3CBJHMDH8KoSqjoXRGWVPbGQEH8RM","versionTime":"2012-12-12T12:12:13Z","parameters":{"deactivated":true,"updateKeys":[]},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmPLFTzZ7p5ekx2XkPRsC4Kn5xYWLVHEsG2jHvzZRqhorj:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:13Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"assertionMethod","proofValue":"z3NJ1JFdFer5gNCfWvg3nbLKXkviV8o6SmEexS5ogYWz6r3JmfLhA4pKW1sS1w7nbLN7DM6sXspifAzcmRLkTNZEL"}]}
                """.contains(finalUpdatedDidLog));

        assertDoesNotThrow(() -> {
            assertEquals(2, WebVerifiableHistoryDidLogMetaPeeker.peek(finalUpdatedDidLog).getLastVersionNumber()); // there should be another entry i.e. one more
            new Did(WebVerifiableHistoryDidLogMetaPeeker.peek(initialDidLogEntry).getDidDoc().getId()).resolveAll(finalUpdatedDidLog); // the ultimate test
        });
    }

    @Test
    void testUpdateAlreadyDeactivatedThrowsWebVerifiableHistoryUpdaterException() {

        // Also features an updateKey matching VERIFICATION_METHOD_KEY_PROVIDER
        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(WebVerifiableHistoryDeactivator.builder()
                    .verificationMethodKeyProvider(TEST_CRYPTO_SUITE)
                    //.verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS) // using a whole another verification key provider
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        assertDeactivatedDidLogEntry(nextLogEntry.get());

        // Try updating the DID log
        var updaterExc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            WebVerifiableHistoryUpdater.builder()
                    .verificationMethodKeyProvider(TEST_CRYPTO_SUITE)
                    .build()
                    .updateDidLog(new StringBuilder(initialDidLogEntry).append(System.lineSeparator()).append(nextLogEntry.get()).toString(),
                            // The versionTime for each log entry MUST be greater than the previous entry’s time.
                            // The versionTime of the last entry MUST be earlier than the current time.
                            ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(2));
        });
        assertEquals("DID already deactivated", updaterExc.getMessage());
    }

    @Test
    void testDeactivateAlreadyDeactivatedThrowsWebVerifiableHistoryDeactivatorException() {

        // Also features an updateKey matching VERIFICATION_METHOD_KEY_PROVIDER
        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(WebVerifiableHistoryDeactivator.builder()
                    .verificationMethodKeyProvider(TEST_CRYPTO_SUITE)
                    //.verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS) // using a whole another verification key provider
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        assertDeactivatedDidLogEntry(nextLogEntry.get());

        deactivatedDidLog.append(nextLogEntry.get()).append(System.lineSeparator());

        // trying to deactivate it again should fail
        var exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            nextLogEntry.set(WebVerifiableHistoryDeactivator.builder()
                    //.verificationMethodKeyProvider(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER) // is actually irrelevant for the test case
                    //.verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS) // using a whole another verification key provider
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(2))); // MUT
        });
        assertEquals("DID already deactivated", exc.getMessage());
    }
}
