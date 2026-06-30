package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.IncompleteDidLogEntryBuilderException;
import ch.admin.bj.swiyu.didtoolbox.model.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.model.NamedDidMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.model.TdwDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all the PMD warnings in this (test) class
@SuppressWarnings("PMD")
class TdwDeactivatorTest extends AbstractUtilTestBase {

    private static void assertDeactivatedDidLogEntry(String didLogEntry, String didLog) {
        assertNotNull(didLogEntry);
        assertTrue(JsonParser.parseString(didLogEntry).isJsonArray());
        JsonArray jsonArray = JsonParser.parseString(didLogEntry).getAsJsonArray();

        assertTrue(jsonArray.get(2).isJsonObject());
        var params = jsonArray.get(2).getAsJsonObject();
        assertEquals(2, params.size()); // only "deactivated" (true) and optionally "updateKeys" (empty) expected
        assertTrue(params.has("deactivated")); // essential
        assertTrue(params.get("deactivated").getAsBoolean()); // essential
        assertTrue(params.has(NamedDidMethodParameters.UPDATE_KEYS));
        assertTrue(params.get(NamedDidMethodParameters.UPDATE_KEYS).isJsonArray());

        assertTrue(jsonArray.get(3).isJsonObject());
        assertTrue(jsonArray.get(3).getAsJsonObject().has("value"));
        var didDoc = jsonArray.get(3).getAsJsonObject().get("value").getAsJsonObject();
        assertEquals(1, didDoc.size()); // only "id" should be in the didDoc
        assertTrue(didDoc.has("id"));
        assertFalse(didDoc.has("profile_version"));

        var proofs = jsonArray.get(4);
        assertTrue(proofs.isJsonArray());
        assertFalse(proofs.getAsJsonArray().isEmpty());
        var proof = proofs.getAsJsonArray().get(0);
        assertTrue(proof.isJsonObject());
        assertTrue(proof.getAsJsonObject().has("proofValue"));

        var exc = assertThrowsExactly(DidResolveException.InvalidDidDocument.class, () -> {
            var did = new Did(didDoc.get("id").getAsString());
            did.resolveAll(didLog); // sanity check
        });
        assertTrue(exc.getMessage().contains("Document has been deactivated"));
    }

    @Test
    void testDeactivateThrowsDeactivationKeyMismatchDidLogDeactivatorStrategyException() {

        var exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            // IMPORTANT Use any suite other than TEST_CRYPTO_SUITE (to provoke the exception)
            TdwDeactivator.builder(new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                    .build()
                    .deactivateDidLog(buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE)); // MUT
        });
        assertEquals("Deactivation key mismatch", exc.getMessage());
    }

    @Test
    void testDeactivateThrowsDateTimeInThePastDidLogDeactivatorStrategyException() {

        var exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            TdwDeactivator.builder(TEST_CRYPTO_SUITE_JKS)
                    .build()
                    .deactivateDidLog( // MUT
                            buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE_JKS),
                            ZonedDateTime.parse(ISO_DATE_TIME).minusMinutes(1)); // In the past!
        });
        assertEquals("The versionTime of the last entry MUST be earlier than the current time", exc.getMessage());
    }

    @Test
    void testDeactivateWithKeyChangeUsingExistingUpdateKey() {

        var initialDidLogEntry = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(TdwDeactivator.builder(TEST_CRYPTO_SUITE_JKS) // using a whole another suite
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        deactivatedDidLog.append(nextLogEntry.get()).append(System.lineSeparator());
        var finalUpdatedDidLog = deactivatedDidLog.toString().trim(); // trimming due to a closing line separator

        assertDeactivatedDidLogEntry(nextLogEntry.get(), finalUpdatedDidLog);
        assertTrue("""
                ["1-QmNeSZVJRWr7AtjJnhJXeKu2d8v8yBVutb2MRmsoSyvxu5","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmbPogn55FwAXeCpvzV1w6ejgUC6pNoPiMNAc85hXti1dA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"],"portable":false},{"value":{"id":"did:tdw:QmbPogn55FwAXeCpvzV1w6ejgUC6pNoPiMNAc85hXti1dA:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmbPogn55FwAXeCpvzV1w6ejgUC6pNoPiMNAc85hXti1dA:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:tdw:QmbPogn55FwAXeCpvzV1w6ejgUC6pNoPiMNAc85hXti1dA:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmbPogn55FwAXeCpvzV1w6ejgUC6pNoPiMNAc85hXti1dA:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","controller":"did:tdw:QmbPogn55FwAXeCpvzV1w6ejgUC6pNoPiMNAc85hXti1dA:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmbPogn55FwAXeCpvzV1w6ejgUC6pNoPiMNAc85hXti1dA:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","controller":"did:tdw:QmbPogn55FwAXeCpvzV1w6ejgUC6pNoPiMNAc85hXti1dA:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","proofPurpose":"authentication","challenge":"1-QmNeSZVJRWr7AtjJnhJXeKu2d8v8yBVutb2MRmsoSyvxu5","proofValue":"z5Eapsb1do21pGsUTCECbdvWDi9ooJ5sGSVgT182mMD8JsMzKqLpex8jE1514Qs5E85M2DaSijgF6VrPvzyYU2SkB"}]]
                ["2-QmZHP9FSVKaztnBo2meb3cxcBYwNwjZWfitQ6uzPEFtr3a","2012-12-12T12:12:13Z",{"deactivated":true,"updateKeys":[]},{"value":{"id":"did:tdw:QmbPogn55FwAXeCpvzV1w6ejgUC6pNoPiMNAc85hXti1dA:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:13Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"2-QmZHP9FSVKaztnBo2meb3cxcBYwNwjZWfitQ6uzPEFtr3a","proofValue":"z52ZbtJHM2Yb3HfgG2GTNJnvBT6jYNrLKNZga2sBUrtN5i5pTe3p22UfpL4sEN9raSBVYjTWuH5n4UvCArZZ3SkBq"}]]
                """.contains(finalUpdatedDidLog));

        var e = assertThrowsExactly(DidLogMetaPeekerException.class, () -> {
            TdwDidLogMetaPeeker.peek(finalUpdatedDidLog); // should throw exception as did log has been deactivated
        });
        assertTrue(e.getMessage().contains("Document has been deactivated"));
    }

    @Test
    void testUpdateAlreadyDeactivatedThrowsDidLogUpdaterStrategyException() {

        var initialDidLogEntry = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder didLogToDeactivate = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(TdwDeactivator.builder(TEST_CRYPTO_SUITE)
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(didLogToDeactivate.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        var didLogDeactivated = initialDidLogEntry + System.lineSeparator() + nextLogEntry.get();
        assertDeactivatedDidLogEntry(nextLogEntry.get(), didLogDeactivated);

        // Try updating the DID log
        var updaterExc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            TdwUpdater.builder(TEST_CRYPTO_SUITE)
                    .build()
                    .updateDidLog(didLogDeactivated,
                            // The versionTime for each log entry MUST be greater than the previous entry’s time.
                            // The versionTime of the last entry MUST be earlier than the current time.
                            ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(2));
        });
        assertTrue(updaterExc.getMessage().contains("Document has been deactivated"));
    }

    @Test
    void testDeactivateAlreadyDeactivatedThrowsDidLogDeactivatorStrategyException() {

        var initialDidLogEntry = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder didLogToDeactivate = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(TdwDeactivator.builder(TEST_CRYPTO_SUITE)
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(didLogToDeactivate.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        var didLogDeactivated = didLogToDeactivate.append(nextLogEntry.get()).append(System.lineSeparator()).toString();

        assertDeactivatedDidLogEntry(nextLogEntry.get(), didLogDeactivated);

        // trying to deactivate it again should fail
        var exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            nextLogEntry.set(TdwDeactivator.builder(TEST_CRYPTO_SUITE)
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(didLogToDeactivate.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(2))); // MUT
        });
        assertTrue(exc.getMessage().contains("Document has been deactivated"));
    }

    @DisplayName("Deactivating DID log without cryptographic suite throws IncompleteDidLogEntryBuilderException")
    @Test
    void testDeactivateDidLogWithoutCryptographicSuiteThrowsIncompleteDidLogEntryBuilderException() {

        var initialDidLogEntry = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        var exc = assertThrowsExactly(IncompleteDidLogEntryBuilderException.class, () -> {
            // IMPORTANT provide null as crypto suite intentionally (no cryptographic suite supplied) to provoke the exception
            TdwDeactivator.builder(null)
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(2)); // MUT
        });
        assertTrue(exc.getMessage().contains("No cryptographic suite supplied"));
    }
}
