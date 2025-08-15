package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didresolver.Did;
import com.google.gson.JsonArray;
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

class TdwUpdaterTest extends AbstractUtilTestBase {

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
        assertTrue(JsonParser.parseString(didLogEntry).isJsonArray());
        JsonArray jsonArray = JsonParser.parseString(didLogEntry).getAsJsonArray();

        assertTrue(jsonArray.get(2).isJsonObject());
        var params = jsonArray.get(2).getAsJsonObject();
        //assertTrue(params.has("method"));
        //assertTrue(params.has("scid"));
        //assertTrue(params.has("updateKeys"));

        assertTrue(jsonArray.get(3).isJsonObject());
        assertTrue(jsonArray.get(3).getAsJsonObject().has("value"));
        var didDoc = jsonArray.get(3).getAsJsonObject().get("value").getAsJsonObject();
        assertTrue(didDoc.has("id"));
        assertTrue(didDoc.has("authentication"));
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

        var proofs = jsonArray.get(4);
        assertTrue(proofs.isJsonArray());
        assertFalse(proofs.getAsJsonArray().isEmpty());
        var proof = proofs.getAsJsonArray().get(0);
        assertTrue(proof.isJsonObject());
        assertTrue(proof.getAsJsonObject().has("proofValue"));
    }

    @Test
    void testUpdateThrowsUpdateKeyMismatchTdwUpdaterException() {

        var exc = assertThrowsExactly(TdwUpdaterException.class, () -> {

            TdwUpdater.builder()
                    // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .update(buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS)); // MUT
        });
        assertEquals("Update key mismatch", exc.getMessage());

        exc = assertThrowsExactly(TdwUpdaterException.class, () -> {
            TdwUpdater.builder()
                    .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER) // using another verification key provider...
                    .updateKeys(Set.of(new File("src/test/data/public.pem"))) // ...with NO matching key supplied!
                    .build()
                    .update(buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS)); // MUT
        });
        assertEquals("Update key mismatch", exc.getMessage());
    }

    @Test
    void testUpdateThrowsDateTimeInThePastTdwUpdaterException() {

        var exc = assertThrowsExactly(TdwUpdaterException.class, () -> {
            TdwUpdater.builder()
                    .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS)
                    .build()
                    .update( // MUT
                            buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS),
                            ZonedDateTime.parse(ISO_DATE_TIME).minusMinutes(1)); // In the past!
        });
        assertEquals("The versionTime of the last entry MUST be earlier than the current time", exc.getMessage());
    }

    @Test
    void testUpdateWithKeyChangeUsingExistingUpdateKey() {

        // Also features an updateKey matching VERIFICATION_METHOD_KEY_PROVIDER
        var initialDidLogEntry = buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER);

        String nextLogEntry = null;
        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder updatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        try {

            nextLogEntry = TdwUpdater.builder()
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
        var params = JsonParser.parseString(nextLogEntry).getAsJsonArray().get(2).getAsJsonObject();
        assertFalse(params.has("updateKeys")); // no new updateKeys, really

        updatedDidLog.append(nextLogEntry).append(System.lineSeparator());

        var finalUpdatedDidLog = updatedDidLog.toString().trim(); // trimming due to a closing line separator
        // System.out.println(finalUpdatedDidLog); // checkpoint
        assertDoesNotThrow(() -> {
            assertEquals(2, DidLogMetaPeeker.peek(finalUpdatedDidLog).lastVersionNumber); // there should be another entry i.e. one more
            new Did(DidLogMetaPeeker.peek(initialDidLogEntry).didDocId).resolve(finalUpdatedDidLog); // the ultimate test
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
        var initialDidLogEntry = buildInitialTdwDidLogEntry(verificationMethodKeyProvider);

        String nextLogEntry = null;
        // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
        StringBuilder updatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());

        try {

            nextLogEntry = TdwUpdater.builder()
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
        var params = JsonParser.parseString(nextLogEntry).getAsJsonArray().get(2).getAsJsonObject();
        assertTrue(params.has("updateKeys"));
        assertTrue(params.get("updateKeys").isJsonArray());
        assertFalse(params.get("updateKeys").getAsJsonArray().isEmpty());
        assertEquals(2, params.get("updateKeys").getAsJsonArray().size()); // a new one

        updatedDidLog.append(nextLogEntry).append(System.lineSeparator());

        var finalUpdatedDidLog = updatedDidLog.toString().trim(); // trimming due to a closing line separator
        // System.out.println(finalUpdatedDidLog); // checkpoint
        assertDoesNotThrow(() -> {
            assertEquals(2, DidLogMetaPeeker.peek(finalUpdatedDidLog).lastVersionNumber); // there should be another entry i.e. one more
            new Did(DidLogMetaPeeker.peek(initialDidLogEntry).didDocId).resolve(finalUpdatedDidLog); // the ultimate test
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
        var initialDidLogEntry = buildInitialTdwDidLogEntry(verificationMethodKeyProvider);

        String nextLogEntry = null;
        StringBuilder updatedDidLog = null;
        int totalEntriesCount = 5;
        try {

            // CAUTION The line separator is appended intentionally - to be able to reproduce the case with multiple line separators
            updatedDidLog = new StringBuilder(initialDidLogEntry).append(System.lineSeparator());
            for (int i = 2; i < totalEntriesCount + 1; i++) { // update DID log by adding several new entries

                nextLogEntry = TdwUpdater.builder()
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
        // System.out.println(finalUpdatedDidLog); // checkpoint
        assertDoesNotThrow(() -> {
            assertEquals(totalEntriesCount, DidLogMetaPeeker.peek(finalUpdatedDidLog).lastVersionNumber); // the loop should have created that many
            new Did(DidLogMetaPeeker.peek(finalUpdatedDidLog).didDocId).resolve(finalUpdatedDidLog); // the ultimate test
        });
    }
}
