package ch.admin.bj.swiyu.didtoolbox.webvh;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.IncompleteDidLogEntryBuilderException;
import ch.admin.bj.swiyu.didtoolbox.model.NamedDidMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.model.WebVerifiableHistoryDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.eid.didresolver.Did;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
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
        assertEquals(1, didDoc.size()); // only "id" should be in the didDoc
        assertTrue(didDoc.has("id"));

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
                    .cryptographicSuite(new EdDsaJcs2022VcDataIntegrityCryptographicSuite()) // any suite other than TEST_CRYPTO_SUITE
                    .build()
                    .deactivateDidLog(buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE)); // MUT
        });
        assertEquals("Deactivation key mismatch", exc.getMessage());
    }

    @Test
    void testDeactivateThrowsDateTimeInThePastWebVerifiableHistoryDeactivatorException() {

        var exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            WebVerifiableHistoryDeactivator.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE_JKS)
                    .build()
                    .deactivateDidLog( // MUT
                            buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS),
                            ZonedDateTime.parse(ISO_DATE_TIME).minusMinutes(1)); // In the past!
        });
        assertEquals("The versionTime of the last entry MUST be earlier than the current time", exc.getMessage());
    }

    @Test
    void testDeactivateWithKeyChangeUsingExistingUpdateKey() {

        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(WebVerifiableHistoryDeactivator.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE_JKS) // using a whole another suite
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
                {"versionId":"1-QmSDurCmSgHMgcQHe2cAc4dDgANa551kLp4gxpYqWRb8mf","versionTime":"2012-12-12T12:12:12Z","parameters":{"method":"did:webvh:1.0","scid":"QmSmrtuRLbn8GBqxb3zGbfSitW4uAXyPVjXeUBmqrcKMb1","updateKeys":["z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},"state":{"id":"did:webvh:QmSmrtuRLbn8GBqxb3zGbfSitW4uAXyPVjXeUBmqrcKMb1:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:webvh:QmSmrtuRLbn8GBqxb3zGbfSitW4uAXyPVjXeUBmqrcKMb1:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:webvh:QmSmrtuRLbn8GBqxb3zGbfSitW4uAXyPVjXeUBmqrcKMb1:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmSmrtuRLbn8GBqxb3zGbfSitW4uAXyPVjXeUBmqrcKMb1:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","controller":"did:webvh:QmSmrtuRLbn8GBqxb3zGbfSitW4uAXyPVjXeUBmqrcKMb1:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:webvh:QmSmrtuRLbn8GBqxb3zGbfSitW4uAXyPVjXeUBmqrcKMb1:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","controller":"did:webvh:QmSmrtuRLbn8GBqxb3zGbfSitW4uAXyPVjXeUBmqrcKMb1:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","proofPurpose":"assertionMethod","proofValue":"z5B1PYbAaemvxvGn3ck3nVfr1UjwTJdgL8bHQF8esBkP6z9szL8cxkAoFNhbJYcLwGa1vQ664DUWisgkHAhzmyLN2"}]}
                {"versionId":"2-QmSD28MPxAzVjrN7LnqtfdjfEfcRRbJJpi87JDRxpEpnpJ","versionTime":"2012-12-12T12:12:13Z","parameters":{"deactivated":true,"updateKeys":[]},"state":{"id":"did:webvh:QmSmrtuRLbn8GBqxb3zGbfSitW4uAXyPVjXeUBmqrcKMb1:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:13Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"assertionMethod","proofValue":"z2Xbn2HLfEPUfHYWa69EeF7AauiKVwvzZiN7j368UHbSrLV9EDkVZthm5xZ9soS1wEtu4XWUgjsgRkkbHymTESmyh"}]}
                """.contains(finalUpdatedDidLog));

        assertDoesNotThrow(() -> {
            assertEquals(2, WebVerifiableHistoryDidLogMetaPeeker.peek(finalUpdatedDidLog).getLastVersionNumber()); // there should be another entry i.e. one more
            new Did(WebVerifiableHistoryDidLogMetaPeeker.peek(initialDidLogEntry).getDidDoc().getId()).resolveAll(finalUpdatedDidLog); // the ultimate test
        });
    }

    @Test
    void testUpdateAlreadyDeactivatedThrowsWebVerifiableHistoryUpdaterException() {

        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(WebVerifiableHistoryDeactivator.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE)
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        assertDeactivatedDidLogEntry(nextLogEntry.get());

        // Try updating the DID log
        var updaterExc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            WebVerifiableHistoryUpdater.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE)
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

        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(WebVerifiableHistoryDeactivator.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE)
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
                    .cryptographicSuite(TEST_CRYPTO_SUITE)
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(2))); // MUT
        });
        assertEquals("DID already deactivated", exc.getMessage());
    }

    @DisplayName("Deactivating DID log without cryptographic suite throws IncompleteDidLogEntryBuilderException")
    @Test
    public void testDeactivateDidLogWithoutCryptographicSuiteThrowsIncompleteDidLogEntryBuilderException() {

        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        var exc = assertThrowsExactly(IncompleteDidLogEntryBuilderException.class, () -> {
            WebVerifiableHistoryDeactivator.builder()
                    // IMPORTANT A .cryptographicSuite() call is omitted intentionally (no cryptographic suite supplied) to provoke the exception
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(2)); // MUT
        });
        assertTrue(exc.getMessage().contains("No cryptographic suite supplied"));
    }
}
