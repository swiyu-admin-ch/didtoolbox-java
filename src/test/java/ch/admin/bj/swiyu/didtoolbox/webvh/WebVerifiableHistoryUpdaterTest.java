package ch.admin.bj.swiyu.didtoolbox.webvh;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.JCSHasher;
import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.model.NamedDidMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.model.UpdateKeysDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.model.WebVerifiableHistoryDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.eid.didresolver.Did;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all the PMD warnings in this (test) class
@SuppressWarnings("PMD")
class WebVerifiableHistoryUpdaterTest extends AbstractUtilTestBase {

    private static void assertDidLogEntry(String didLogEntry) {

        assertNotNull(didLogEntry);
        assertTrue(JsonParser.parseString(didLogEntry).isJsonObject());
        var jsonObject = JsonParser.parseString(didLogEntry).getAsJsonObject();

        assertTrue(jsonObject.get("parameters").isJsonObject());
        assertFalse(jsonObject.get("parameters").isJsonNull());
        //assertTrue(jsonObject.get("parameters").getAsJsonObject().isEmpty());
        //var params = jsonObject.get("parameters").getAsJsonObject();
        //assertTrue(params.has("method"));
        //assertTrue(params.has("scid"));
        //assertTrue(params.has(NamedDidMethodParameters.UPDATE_KEYS));
        //assertTrue(params.get(NamedDidMethodParameters.UPDATE_KEYS).isJsonArray());

        assertTrue(jsonObject.get("state").isJsonObject());
        var didDoc = jsonObject.get("state").getAsJsonObject();
        assertTrue(didDoc.has("id"));
        assertTrue(didDoc.get("authentication").isJsonArray());
        var authentication = didDoc.get("authentication").getAsJsonArray();
        assertFalse(authentication.isEmpty());
        assertTrue(didDoc.has("assertionMethod"));
        assertTrue(didDoc.get("assertionMethod").isJsonArray());
        var assertionMethod = didDoc.get("assertionMethod").getAsJsonArray();
        assertFalse(assertionMethod.isEmpty());
        assertTrue(didDoc.has("verificationMethod"));
        assertTrue(didDoc.get("verificationMethod").isJsonArray());
        var verificationMethod = didDoc.get("verificationMethod").getAsJsonArray();
        assertFalse(verificationMethod.isEmpty());

        var proofs = jsonObject.get("proof");
        assertTrue(proofs.isJsonArray());
        assertFalse(proofs.getAsJsonArray().isEmpty());
        var proof = proofs.getAsJsonArray().get(0);
        assertTrue(proof.isJsonObject());
        var proofJsonObj = proof.getAsJsonObject();
        assertTrue(proofJsonObj.has("type"));
        assertEquals(JCSHasher.DATA_INTEGRITY_PROOF, proofJsonObj.get("type").getAsString());
        assertTrue(proofJsonObj.has("cryptosuite"));
        assertEquals(JCSHasher.EDDSA_JCS_2022, proofJsonObj.get("cryptosuite").getAsString());
        assertTrue(proofJsonObj.has("verificationMethod"));
        assertTrue(proofJsonObj.get("verificationMethod").getAsString().startsWith(JCSHasher.DID_KEY));
        assertTrue(proofJsonObj.has("created"));
        /*
        https://identity.foundation/didwebvh/v1.0/#create-register:
        "5.5. Generate the Data Integrity proof: A Data Integrity proof on the preliminary JSON object as updated in the
        previous step MUST be generated using an authorized key in the required updateKeys property in the parameters
        object and the proofPurpose set to assertionMethod."
         */
        assertTrue(proofJsonObj.has("proofPurpose"));
        assertEquals(JCSHasher.PROOF_PURPOSE_ASSERTION_METHOD, proofJsonObj.get("proofPurpose").getAsString());
        assertTrue(proofJsonObj.has("proofValue"));
    }

    @Test
    void testUpdateDidLogThrowsUpdateKeyMismatchDidLogUpdaterStrategyException() {

        var exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {

            WebVerifiableHistoryUpdater.builder()
                    // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .updateDidLog(buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS)); // MUT
        });
        assertEquals("Update key mismatch", exc.getMessage());

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            WebVerifiableHistoryUpdater.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using a whole another verification key provider
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of(TEST_DATA_PATH_PREFIX + "public.pem")))) // ...with NO matching key supplied!
                    .build()
                    .updateDidLog(buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS)); // MUT
        });
        assertEquals("Update key mismatch", exc.getMessage());
    }

    @Test
    void testUpdateDidLogThrowsDateTimeInThePastDidLogUpdaterStrategyException() {

        var exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            WebVerifiableHistoryUpdater.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE_JKS)
                    .build()
                    .updateDidLog( // MUT
                            buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS),
                            ZonedDateTime.parse(ISO_DATE_TIME).minusMinutes(1)); // In the past!
        });
        assertEquals("The versionTime of the last entry MUST be earlier than the current time", exc.getMessage());
    }

    @Test
    void testUpdateDidLogWithKeyAlternationUsingExistingUpdateKey() {

        // Also features an updateKey matching VERIFICATION_METHOD_KEY_PROVIDER
        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE);

        String nextLogEntry = null;
        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder updatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        try {

            nextLogEntry = WebVerifiableHistoryUpdater.builder()
                    //.verificationMethodKeyProvider(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER)
                    .cryptographicSuite(TEST_CRYPTO_SUITE_JKS) // using a whole another verification key provider
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    // CAUTION No need for explicit call of method: .updateKeys(Set.of(new File("src/test/data/public.pem")))
                    //         The updateKey matching VERIFICATION_METHOD_KEY_PROVIDER is already present in initialDidLogEntry.
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .updateDidLog(updatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1)); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(nextLogEntry);

        // At this point should be all fine with the nextLogEntry i.e. it is sufficient just to check on updateKeys
        var params = JsonParser.parseString(nextLogEntry).getAsJsonObject().get("parameters").getAsJsonObject();
        assertFalse(params.has(NamedDidMethodParameters.UPDATE_KEYS)); // no new updateKeys, really

        updatedDidLog.append(nextLogEntry).append(System.lineSeparator());

        var finalUpdatedDidLog = updatedDidLog.toString().trim(); // trimming due to a closing line separator
        // System.out.println(finalUpdatedDidLog); // checkpoint
        assertDoesNotThrow(() -> {
            assertEquals(2, WebVerifiableHistoryDidLogMetaPeeker.peek(finalUpdatedDidLog).getLastVersionNumber()); // there should be another entry i.e. one more
            new Did(WebVerifiableHistoryDidLogMetaPeeker.peek(initialDidLogEntry).getDidDoc().getId()).resolveAll(finalUpdatedDidLog); // the ultimate test
        });
    }

    @DisplayName("Updating DID log by using another (pre-rotation) key")
    @Test
    void testUpdateDidLogWithKeyPrerotation() {

        // The initial entry features 2 pre-rotation keys, both eligible for updating the DID log
        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntryWithKeyPrerotation(
                Set.of(
                        new File(TEST_DATA_PATH_PREFIX + "public.pem"), // matches TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS
                        new File(TEST_DATA_PATH_PREFIX + "public01.pem") // matches TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER
                ));

        // Once the 'nextKeyHashes' parameter has been set to a non-empty array, Key Pre-Rotation is active.
        // While active, the properties 'nextKeyHashes' and 'updateKeys' MUST be present in all log entries.
        assertTrue(JsonParser.parseString(initialDidLogEntry).getAsJsonObject().get("parameters").getAsJsonObject().has(NamedDidMethodParameters.NEXT_KEY_HASHES)); // denotes key pre-rotation

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder updatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        assertDoesNotThrow(() -> {
            nextLogEntry.set(WebVerifiableHistoryUpdater.builder()
                    // 1st key supplied implicitly via VerificationMethodKeyProvider:
                    //     Given the setup of initialDidLogEntry (see above), either of TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS and
                    //     TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER must work
                    .cryptographicSuite(TEST_CRYPTO_SUITE_JKS) // using a whole another verification key provider
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    // 2nd updateKey supplied explicitly (from file)
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(
                            //new File(TEST_DATA_PATH_PREFIX + "public.pem"), // matches TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS
                            Path.of(TEST_DATA_PATH_PREFIX + "public01.pem") // matches TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER
                    )))
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .updateDidLog(updatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        assertDidLogEntry(nextLogEntry.get());

        // Once the nextKeyHashes parameter has been set to a non-empty array, Key Pre-Rotation is active.
        // While active, the properties nextKeyHashes and updateKeys MUST be present in all log entries.
        var params = JsonParser.parseString(nextLogEntry.get()).getAsJsonObject().get("parameters").getAsJsonObject();
        assertTrue(params.has(NamedDidMethodParameters.UPDATE_KEYS));
        //assertTrue(params.has(NamedDidMethodParameters.NEXT_KEY_HASHES));

        updatedDidLog.append(nextLogEntry.get()).append(System.lineSeparator());
        //System.out.println(updatedDidLog);

        var finalUpdatedDidLog = updatedDidLog.toString().trim(); // trimming due to a closing line separator
        // System.out.println(finalUpdatedDidLog); // checkpoint
        assertDoesNotThrow(() -> {
            assertEquals(2, WebVerifiableHistoryDidLogMetaPeeker.peek(finalUpdatedDidLog).getLastVersionNumber()); // there should be another entry i.e. one more
            new Did(WebVerifiableHistoryDidLogMetaPeeker.peek(initialDidLogEntry).getDidDoc().getId()).resolveAll(finalUpdatedDidLog); // the ultimate test
        });
    }

    @Test
    void testUpdateDidLogWithKeyPrerotationThrowsUpdateKeyMismatchDidLogUpdaterStrategyException() {

        // The initial entry features pre-rotation key(s), eligible for the DID log update
        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntryWithKeyPrerotation(
                Set.of(
                        //new File(TEST_DATA_PATH_PREFIX + "public.pem"), // matches TEST_VERIFICATION_METHOD_KEY_PROVIDER
                        new File(TEST_DATA_PATH_PREFIX + "public01.pem") // matches TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER
                ));

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder updatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        var exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            WebVerifiableHistoryUpdater.builder()
                    // IMPORTANT Let the builder set any VerificationMethodKeyProvider itself, as long as it delivers a key different than the one from initial entry
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .updateDidLog(updatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1)); // MUT
        });
        assertEquals("Update key mismatch", exc.getMessage());
    }

    @Test
    void testUpdateDidLogWithKeyPrerotationThrowsIllegalUpdateKeyDidLogUpdaterStrategyException() {

        // The initial entry features pre-rotation key(s), eligible for the DID log update
        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntryWithKeyPrerotation(
                Set.of(
                        //new File(TEST_DATA_PATH_PREFIX + "public.pem"), // matches TEST_VERIFICATION_METHOD_KEY_PROVIDER
                        new File(TEST_DATA_PATH_PREFIX + "public01.pem") // matches TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER
                ));

        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder updatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        var exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            WebVerifiableHistoryUpdater.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE_ANOTHER) // using a whole another verification key provider
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    // IMPORTANT The key does not match TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER thus ILLEGAL
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of(TEST_DATA_PATH_PREFIX + "public.pem"))))
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .updateDidLog(updatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1)); // MUT
        });
        assertEquals("Illegal updateKey detected", exc.getMessage());
    }

    @DisplayName("Updating DID log by alternating between various existing (alternate) keys")
    @Test
    void testUpdateDidLogWithKeyAlternation() {

        // Also features an updateKey matching TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS
        AtomicReference<String> initialDidLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            initialDidLogEntry.set(buildInitialWebVerifiableHistoryDidLogEntry(
                    new EdDsaJcs2022VcDataIntegrityCryptographicSuite(TEST_KEYS[0][0])));
        });

        assertTrue(JsonParser.parseString(initialDidLogEntry.get()).getAsJsonObject().get("parameters").getAsJsonObject().has("updateKeys")); // denotes key pre-rotation

        AtomicReference<String> nextLogEntry = new AtomicReference<>();
        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder updatedDidLog = new StringBuilder(initialDidLogEntry.get()).append(System.lineSeparator());

        assertDoesNotThrow(() -> {
            nextLogEntry.set(WebVerifiableHistoryUpdater.builder()
                    // using already available verification method key provider
                    .cryptographicSuite(TEST_CRYPTO_SUITE_JKS)
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    // CAUTION Trying to explicitly set 'updateKeys' by calling .updateKeys(...) results in error condition:
                    //         "invalid DID method parameter: invalid DID parameter: Invalid update key found. UpdateKey may only be set during key pre-rotation."
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .updateDidLog(updatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1))); // MUT
        });

        assertDidLogEntry(nextLogEntry.get());

        // At this point should be all fine with the nextLogEntry

        updatedDidLog.append(nextLogEntry.get()).append(System.lineSeparator());

        var finalUpdatedDidLog = updatedDidLog.toString().trim(); // trimming due to a closing line separator
        //System.out.println(finalUpdatedDidLog); // checkpoint

        assertDoesNotThrow(() -> {
            assertEquals(2, WebVerifiableHistoryDidLogMetaPeeker.peek(finalUpdatedDidLog).getLastVersionNumber()); // there should be another entry i.e. one more
            var resolveAll = new Did(WebVerifiableHistoryDidLogMetaPeeker.peek(initialDidLogEntry.get()).getDidDoc().getId()).resolveAll(finalUpdatedDidLog); // the ultimate test
            // At this point, it is sufficient just to check on 'updateKeys'
            var params = resolveAll.getDidMethodParameters();
            assertTrue(params.containsKey(NamedDidMethodParameters.UPDATE_KEYS));
            var updateKeys = params.get(NamedDidMethodParameters.UPDATE_KEYS);
            assertTrue(updateKeys.isArray());
            assertFalse(updateKeys.isEmptyArray());
            assertNotNull(updateKeys.getStringArrayValue());
            assertEquals(2, updateKeys.getStringArrayValue().size()); // publicKeyMultibase + another one supplied via
            assertTrue(updateKeys.getStringArrayValue().contains(TEST_KEYS[0][1]));
        });
    }

    @DisplayName("Multiple update of DID log using various existing (alternate) keys")
    @Test
    void testMultipleUpdateDidLogWithKeyAlternation() {

        var verificationMethodKeyProvider = TEST_CRYPTO_SUITES[0]; // irrelevant
        // Also features an updateKey matching TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS
        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntry(verificationMethodKeyProvider);

        // Available key providers to use when updating
        var keyProviders = new VcDataIntegrityCryptographicSuite[]{
                verificationMethodKeyProvider,
                TEST_CRYPTO_SUITE_JKS,
        };

        //String nextLogEntry;
        AtomicReference<StringBuilder> updatedDidLog = new AtomicReference<>();
        int totalEntriesCount = 5;
        assertDoesNotThrow(() -> {

            // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
            updatedDidLog.set(new StringBuilder(initialDidLogEntry).append(System.lineSeparator()));
            for (int i = 2; i < totalEntriesCount + 1; i++) { // update DID log by adding several new entries

                // Alternate between available key providers
                var keyProvider = keyProviders[i % 2];

                var nextLogEntry = WebVerifiableHistoryUpdater.builder()
                        .cryptographicSuite(keyProvider) // different for odd and even entries (key alternation)
                        .assertionMethodKeys(Map.of("my-assert-key-0" + i, JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/assert-key-01.pub"), "my-assert-key-0" + i)))
                        .authenticationKeys(Map.of("my-auth-key-0" + i, JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/auth-key-01.pub"), "my-auth-key-0" + i)))
                        // CAUTION Trying to explicitly set 'updateKeys' by calling .updateKeys(...) results in error condition:
                        //         "invalid DID method parameter: invalid DID parameter: Invalid update key found. UpdateKey may only be set during key pre-rotation."
                        .build()
                        // The versionTime for each log entry MUST be greater than the previous entry’s time.
                        // The versionTime of the last entry MUST be earlier than the current time.
                        .updateDidLog(updatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(i - 1)); // MUT

                assertDidLogEntry(nextLogEntry);

                updatedDidLog.get().append(nextLogEntry).append(System.lineSeparator());
            }

        });

        var finalUpdatedDidLog = updatedDidLog.toString().trim(); // trimming due to a closing line separator
        //System.out.println(finalUpdatedDidLog); // checkpoint
        assertDoesNotThrow(() -> {
            assertEquals(totalEntriesCount, WebVerifiableHistoryDidLogMetaPeeker.peek(finalUpdatedDidLog).getLastVersionNumber()); // the loop should have created that many
            new Did(WebVerifiableHistoryDidLogMetaPeeker.peek(finalUpdatedDidLog).getDidDoc().getId()).resolveAll(finalUpdatedDidLog); // the ultimate test
        });
    }

    @DisplayName("Multiple update of DID log using various existing (pre-rotation) keys")
    @Test
    void testMultipleUpdateDidLogWithKeyPrerotation() {

        var initialDidLogEntry = buildInitialWebVerifiableHistoryDidLogEntryWithKeyPrerotation(Set.of(
                TEST_KEY_FILES[0] // the (single) pre-rotation key to be used when building the next DID log entry
        ));

        assertTrue(JsonParser.parseString(initialDidLogEntry).getAsJsonObject().get("parameters").getAsJsonObject().has("updateKeys")); // denotes key pre-rotation

        AtomicReference<StringBuilder> updatedDidLog = new AtomicReference<>();
        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        updatedDidLog.set(new StringBuilder(initialDidLogEntry).append(System.lineSeparator()));
        assertDoesNotThrow(() -> {

            // Update DID log by adding as many entries as there are keys. Keep "rotating" keys while updating
            for (int i = 2; i < TEST_KEY_FILES.length + 1; i++) {

                String nextLogEntry = WebVerifiableHistoryUpdater.builder()
                        .cryptographicSuite(TEST_CRYPTO_SUITES[i - 2]) // rotate to the key defined by the previous entry
                        .assertionMethodKeys(Map.of("my-assert-key-0" + i, JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/assert-key-01.pub"), "my-assert-key-0" + i)))
                        .authenticationKeys(Map.of("my-auth-key-0" + i, JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/auth-key-01.pub"), "my-auth-key-0" + i)))
                        // CAUTION Trying to explicitly set 'updateKeys' by calling .updateKeys(...) results in error condition:
                        //         "invalid DID method parameter: invalid DID parameter: Invalid update key found. UpdateKey may only be set during key pre-rotation."
                        // Using alternative and more potent method to supply pre-rotation keys.
                        // BTW Adding the same key (via another method) has no effect as eventually distinct key values are taken.
                        .nextKeyHashesDidMethodParameter(Set.of(
                                NextKeyHashesDidMethodParameter.of(
                                        TEST_KEY_FILES[i - 1].toPath() // get a whole another (single) pre-rotation key to be used when building the next DID log entry
                                        // CAUTION Adding the same key causes "duplicate element" IllegalArgumentException
                                        //), NextKeyHashesDidMethodParameter.of(
                                        //        TEST_KEYS[i - 1][1] // get a whole another (single) pre-rotation key to be used when building the next DID log entry
                                )))
                        .build()
                        // The versionTime for each log entry MUST be greater than the previous entry’s time.
                        // The versionTime of the last entry MUST be earlier than the current time.
                        .updateDidLog(updatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(i - 1)); // MUT

                assertDidLogEntry(nextLogEntry);

                updatedDidLog.get().append(nextLogEntry).append(System.lineSeparator());
            }
        });

        var finalUpdatedDidLog = updatedDidLog.toString().trim(); // trimming due to a closing line separator
        //System.out.println(finalUpdatedDidLog); // checkpoint
        assertDoesNotThrow(() -> {
            assertEquals(TEST_KEY_FILES.length, WebVerifiableHistoryDidLogMetaPeeker.peek(finalUpdatedDidLog).getLastVersionNumber()); // the loop should have created that many
            new Did(WebVerifiableHistoryDidLogMetaPeeker.peek(finalUpdatedDidLog).getDidDoc().getId()).resolveAll(finalUpdatedDidLog); // the ultimate test
        });
    }
}
