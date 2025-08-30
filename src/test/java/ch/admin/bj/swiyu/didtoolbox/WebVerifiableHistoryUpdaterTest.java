package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.WebVhDidLogMetaPeeker;
import ch.admin.eid.didresolver.Did;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class WebVerifiableHistoryUpdaterTest extends AbstractUtilTestBase {

    public static Collection<Object[]> keys() {
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
        //assertTrue(params.has("updateKeys"));
        //assertTrue(params.get("updateKeys").isJsonArray());

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
    void testUpdateThrowsUpdateKeyMismatchWebVerifiableHistoryUpdaterException() {

        var exc = assertThrowsExactly(WebVerifiableHistoryUpdaterException.class, () -> {

            WebVerifiableHistoryUpdater.builder()
                    // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .update(buildInitialWebVhDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS)); // MUT
        });
        assertEquals("Update key mismatch", exc.getMessage());

        exc = assertThrowsExactly(WebVerifiableHistoryUpdaterException.class, () -> {
            WebVerifiableHistoryUpdater.builder()
                    .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER) // using another verification key provider...
                    .updateKeys(Set.of(new File("src/test/data/public.pem"))) // ...with NO matching key supplied!
                    .build()
                    .update(buildInitialWebVhDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS)); // MUT
        });
        assertEquals("Update key mismatch", exc.getMessage());
    }

    @Test
    void testUpdateThrowsDateTimeInThePastWebVerifiableHistoryUpdaterException() {

        var exc = assertThrowsExactly(WebVerifiableHistoryUpdaterException.class, () -> {
            WebVerifiableHistoryUpdater.builder()
                    .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS)
                    .build()
                    .update( // MUT
                            buildInitialWebVhDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS),
                            ZonedDateTime.parse(ISO_DATE_TIME).minusMinutes(1)); // In the past!
        });
        assertEquals("The versionTime of the last entry MUST be earlier than the current time", exc.getMessage());
    }

    @Test
    void testUpdateWithKeyChangeUsingExistingUpdateKey() {

        // Also features an updateKey matching VERIFICATION_METHOD_KEY_PROVIDER
        var initialDidLogEntry = buildInitialWebVhDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER);

        String nextLogEntry = null;
        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder updatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        try {

            nextLogEntry = WebVerifiableHistoryUpdater.builder()
                    //.verificationMethodKeyProvider(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER)
                    .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS) // using a whole another verification key provider
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    // CAUTION No need for explicit call of method: .updateKeys(Set.of(new File("src/test/data/public.pem")))
                    //         The updateKey matching VERIFICATION_METHOD_KEY_PROVIDER is already present in initialDidLogEntry.
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .update(updatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1)); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(nextLogEntry);

        // At this point should be all fine with the nextLogEntry i.e. it is sufficient just to check on updateKeys
        var params = JsonParser.parseString(nextLogEntry).getAsJsonObject().get("parameters").getAsJsonObject();
        assertFalse(params.has("updateKeys")); // no new updateKeys, really

        updatedDidLog.append(nextLogEntry).append(System.lineSeparator());

        var finalUpdatedDidLog = updatedDidLog.toString().trim(); // trimming due to a closing line separator
        // System.out.println(finalUpdatedDidLog); // checkpoint
        assertDoesNotThrow(() -> {
            assertEquals(2, WebVhDidLogMetaPeeker.peek(finalUpdatedDidLog).getLastVersionNumber()); // there should be another entry i.e. one more
            new Did(WebVhDidLogMetaPeeker.peek(initialDidLogEntry).getDidDoc().getId()).resolveAll(finalUpdatedDidLog); // the ultimate test
        });
    }

    @DisplayName("Updating DID log using various existing keys")
    @ParameterizedTest(name = "Using signing key: {0}")
    @MethodSource("keys")
    void testUpdateWithKeyChange(String privateKeyMultibase, String publicKeyMultibase, String publicKeyPem) {

        File publicKeyPemFile = null;
        try {
            publicKeyPemFile = File.createTempFile("mypublickey", "");
            new Ed25519VerificationMethodKeyProviderImpl().writePublicKeyAsPem(publicKeyPemFile);
        } catch (IOException e) {
            fail(e);
        }
        publicKeyPemFile.deleteOnExit();

        var verificationMethodKeyProvider = new UnsafeEd25519VerificationMethodKeyProviderImpl(privateKeyMultibase, publicKeyMultibase);
        // Also features an updateKey matching VERIFICATION_METHOD_KEY_PROVIDER
        var initialDidLogEntry = buildInitialWebVhDidLogEntry(verificationMethodKeyProvider);

        String nextLogEntry = null;
        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder updatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        try {

            nextLogEntry = WebVerifiableHistoryUpdater.builder()
                    //.verificationMethodKeyProvider(EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER) // using a whole another verification key provider
                    .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS) // using a whole another verification key provider
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .updateKeys(Set.of(new File("src/test/data/public.pem"), publicKeyPemFile))
                    .build()
                    // The versionTime for each log entry MUST be greater than the previous entry’s time.
                    // The versionTime of the last entry MUST be earlier than the current time.
                    .update(updatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(1)); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(nextLogEntry);

        // At this point should be all fine with the nextLogEntry i.e. it is sufficient just to check on updateKeys
        var params = JsonParser.parseString(nextLogEntry).getAsJsonObject().get("parameters").getAsJsonObject();
        assertTrue(params.has("updateKeys"));
        assertTrue(params.get("updateKeys").isJsonArray());
        assertFalse(params.get("updateKeys").getAsJsonArray().isEmpty());
        assertEquals(2, params.get("updateKeys").getAsJsonArray().size()); // a new one

        updatedDidLog.append(nextLogEntry).append(System.lineSeparator());

        var finalUpdatedDidLog = updatedDidLog.toString().trim(); // trimming due to a closing line separator
        // System.out.println(finalUpdatedDidLog); // checkpoint
        assertDoesNotThrow(() -> {
            assertEquals(2, WebVhDidLogMetaPeeker.peek(finalUpdatedDidLog).getLastVersionNumber()); // there should be another entry i.e. one more
            new Did(WebVhDidLogMetaPeeker.peek(initialDidLogEntry).getDidDoc().getId()).resolveAll(finalUpdatedDidLog); // the ultimate test
        });
    }

    @DisplayName("Multiple update of DID log using various existing keys")
    @ParameterizedTest(name = "Using signing key: {0}")
    @MethodSource("keys")
    void testMultipleUpdates(String privateKeyMultibase, String publicKeyMultibase, String publicKeyPem) {

        File publicKeyPemFile = null;
        try {
            publicKeyPemFile = File.createTempFile("mypublickey", "");
            new Ed25519VerificationMethodKeyProviderImpl().writePublicKeyAsPem(publicKeyPemFile);
        } catch (IOException e) {
            fail(e);
        }
        publicKeyPemFile.deleteOnExit();

        var verificationMethodKeyProvider = new UnsafeEd25519VerificationMethodKeyProviderImpl(privateKeyMultibase, publicKeyMultibase);
        // Also features an updateKey matching VERIFICATION_METHOD_KEY_PROVIDER
        var initialDidLogEntry = buildInitialWebVhDidLogEntry(verificationMethodKeyProvider);

        String nextLogEntry;
        StringBuilder updatedDidLog = null;
        int totalEntriesCount = 5;
        try {

            // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
            updatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());
            for (int i = 2; i < totalEntriesCount + 1; i++) { // update DID log by adding several new entries

                nextLogEntry = WebVerifiableHistoryUpdater.builder()
                        .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS) // using another verification key provider
                        .assertionMethodKeys(Map.of("my-assert-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-0" + i)))
                        .authenticationKeys(Map.of("my-auth-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-0" + i)))
                        .updateKeys(Set.of(new File("src/test/data/public.pem"), publicKeyPemFile))
                        .build()
                        // The versionTime for each log entry MUST be greater than the previous entry’s time.
                        // The versionTime of the last entry MUST be earlier than the current time.
                        .update(updatedDidLog.toString(), ZonedDateTime.parse(ISO_DATE_TIME).plusSeconds(i - 1)); // MUT

                assertDidLogEntry(nextLogEntry);

                updatedDidLog.append(nextLogEntry).append(System.lineSeparator());
            }

        } catch (Exception e) {
            fail(e);
        }

        var finalUpdatedDidLog = updatedDidLog.toString().trim(); // trimming due to a closing line separator
        //System.out.println(finalUpdatedDidLog); // checkpoint
        assertDoesNotThrow(() -> {
            assertEquals(totalEntriesCount, WebVhDidLogMetaPeeker.peek(finalUpdatedDidLog).getLastVersionNumber()); // the loop should have created that many
            new Did(WebVhDidLogMetaPeeker.peek(finalUpdatedDidLog).getDidDoc().getId()).resolveAll(finalUpdatedDidLog); // the ultimate test
        });
    }
}
