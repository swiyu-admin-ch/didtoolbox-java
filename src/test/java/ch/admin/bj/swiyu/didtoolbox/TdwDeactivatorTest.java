package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.IncompleteDidLogEntryBuilderException;
import ch.admin.bj.swiyu.didtoolbox.model.NamedDidMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.model.TdwDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.eid.didresolver.Did;
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all the PMD warnings in this (test) class
@SuppressWarnings("PMD")
class TdwDeactivatorTest extends AbstractUtilTestBase {

    private static Collection<Object[]> keys() {
        return Arrays.asList(new String[][]{
                /*
                All lines in the private/public matrix were generated using openssl command by running the following script:

                openssl genpkey -algorithm ed25519 -out private.pem
                openssl pkey -inform pem -in private.pem -outform der -out private.der
                cat private.pem | openssl pkey -pubout -outform der -out public.der
                cat private.pem | openssl pkey -pubout -out public.pem
                secret_key_multibase=z$(echo 8026$(xxd -plain -cols 32 -s -32 private.der) | xxd -r -p | bs58)
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

    private static void assertDeactivatedDidLogEntry(String didLogEntry) {

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

        var proofs = jsonArray.get(4);
        assertTrue(proofs.isJsonArray());
        assertFalse(proofs.getAsJsonArray().isEmpty());
        var proof = proofs.getAsJsonArray().get(0);
        assertTrue(proof.isJsonObject());
        assertTrue(proof.getAsJsonObject().has("proofValue"));
    }

    @Test
    void testDeactivateThrowsDeactivationKeyMismatchDidLogDeactivatorStrategyException() {

        var exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            TdwDeactivator.builder()
                    // IMPORTANT Use any suite other than TEST_CRYPTO_SUITE (to provoke the exception)
                    .cryptographicSuite(new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                    .build()
                    .deactivateDidLog(buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE)); // MUT
        });
        assertEquals("Deactivation key mismatch", exc.getMessage());
    }

    @Test
    void testDeactivateThrowsDateTimeInThePastDidLogDeactivatorStrategyException() {

        var exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            TdwDeactivator.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE_JKS)
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
            nextLogEntry.set(TdwDeactivator.builder()
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
                ["1-QmNUGbKzhqUyuCRmt537qxpQEU5LAGm7udreBhH9QxPxYJ","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmYY7o6wRFPBYfeKK4N7U4TGpXUbgwppG1zKVELxYSuDci","updateKeys":["z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},{"value":{"id":"did:tdw:QmYY7o6wRFPBYfeKK4N7U4TGpXUbgwppG1zKVELxYSuDci:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmYY7o6wRFPBYfeKK4N7U4TGpXUbgwppG1zKVELxYSuDci:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:tdw:QmYY7o6wRFPBYfeKK4N7U4TGpXUbgwppG1zKVELxYSuDci:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmYY7o6wRFPBYfeKK4N7U4TGpXUbgwppG1zKVELxYSuDci:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","controller":"did:tdw:QmYY7o6wRFPBYfeKK4N7U4TGpXUbgwppG1zKVELxYSuDci:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmYY7o6wRFPBYfeKK4N7U4TGpXUbgwppG1zKVELxYSuDci:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","controller":"did:tdw:QmYY7o6wRFPBYfeKK4N7U4TGpXUbgwppG1zKVELxYSuDci:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2","proofPurpose":"authentication","challenge":"1-QmNUGbKzhqUyuCRmt537qxpQEU5LAGm7udreBhH9QxPxYJ","proofValue":"zEYSn9V5casGJH9wUCJDJLHqzTjTQDL11iP3MTzii8RoWdZpbhdYdV9jPTHW8gy9BGS7PweqUVDkaSpGtxUETFmL"}]]
                ["2-Qmci5evTbELsi7nQzp2mM6e7G7DUyobYGVmRAmR59SGijZ","2012-12-12T12:12:13Z",{"deactivated":true,"updateKeys":[]},{"value":{"id":"did:tdw:QmYY7o6wRFPBYfeKK4N7U4TGpXUbgwppG1zKVELxYSuDci:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:13Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"2-Qmci5evTbELsi7nQzp2mM6e7G7DUyobYGVmRAmR59SGijZ","proofValue":"z2zNDbYy1421CToqk5WAXsdAWBL2hHf1xPAm9TvrDA5dsHSgdpz4SBV29UnhanEhbc1RmpUwTYBHFRxC58YrXVCs1"}]]
                """.contains(finalUpdatedDidLog));

        assertDoesNotThrow(() -> {
            assertEquals(2, TdwDidLogMetaPeeker.peek(finalUpdatedDidLog).getLastVersionNumber()); // there should be another entry i.e. one more
            new Did(TdwDidLogMetaPeeker.peek(initialDidLogEntry).getDidDoc().getId()).resolveAll(finalUpdatedDidLog); // the ultimate test
        });
    }

    @Test
    void testUpdateAlreadyDeactivatedThrowsDidLogUpdaterStrategyException() {

        var initialDidLogEntry = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(TdwDeactivator.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE)
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        assertDeactivatedDidLogEntry(nextLogEntry.get());

        // Try updating the DID log
        var updaterExc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            TdwUpdater.builder()
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
    void testDeactivateAlreadyDeactivatedThrowsDidLogDeactivatorStrategyException() {

        var initialDidLogEntry = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            nextLogEntry.set(TdwDeactivator.builder()
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
            nextLogEntry.set(TdwDeactivator.builder()
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

        var initialDidLogEntry = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE);

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder deactivatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        var exc = assertThrowsExactly(IncompleteDidLogEntryBuilderException.class, () -> {
            TdwDeactivator.builder()
                    // IMPORTANT .cryptographicSuite() call is omitted intentionally (no cryptographic suite supplied) to provoke the exception
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .deactivateDidLog(deactivatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(2)); // MUT
        });
        assertTrue(exc.getMessage().contains("No cryptographic suite supplied"));
    }
}
