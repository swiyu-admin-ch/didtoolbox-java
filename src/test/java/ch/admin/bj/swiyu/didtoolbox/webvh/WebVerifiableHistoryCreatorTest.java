package ch.admin.bj.swiyu.didtoolbox.webvh;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.JCSHasher;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.IncompleteDidLogEntryBuilderException;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all PMD warnings in this (test) class
@SuppressWarnings({"PMD"})
public class WebVerifiableHistoryCreatorTest extends AbstractUtilTestBase {

    public static void assertDidLogEntry(String didLogEntry) {
        assertNotNull(didLogEntry);
        assertTrue(JsonParser.parseString(didLogEntry).isJsonObject());
        var jsonObject = JsonParser.parseString(didLogEntry).getAsJsonObject();

        assertTrue(jsonObject.get("parameters").isJsonObject());
        var params = jsonObject.get("parameters").getAsJsonObject();
        assertTrue(params.has("method"));
        assertTrue(params.has("scid"));
        assertTrue(params.has(NamedDidMethodParameters.UPDATE_KEYS));
        assertTrue(params.get(NamedDidMethodParameters.UPDATE_KEYS).isJsonArray());

        assertTrue(jsonObject.get("state").isJsonObject());
        var didDoc = jsonObject.get("state").getAsJsonObject();
        assertTrue(didDoc.has("id"));
        assertTrue(didDoc.has("profile_version"));
        assertEquals("swiss-profile-anchor:1.0.0", didDoc.get("profile_version").getAsString());
        assertTrue(didDoc.get("authentication").isJsonArray());
        assertFalse(didDoc.has("@context"));
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
        Assertions.assertEquals(JCSHasher.DATA_INTEGRITY_PROOF, proofJsonObj.get("type").getAsString());
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

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    void testCreateDidLog(URL identifierRegistryUrl) {
        AtomicReference<String> didLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {

            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(WebVerifiableHistoryCreator.builder(new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                    .authentications(TEST_AUTHENTICATIONS)
                    .assertionMethods(TEST_ASSERTION_METHODS)
                    .build()
                    .createDidLog(identifierRegistryUrl)); // MUT
        });

        assertDidLogEntry(didLogEntry.get());
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (multiple updateKeys)")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    void testCreateDidLogWithMultipleUpdateKeys(URL identifierRegistryUrl) {
        AtomicReference<String> didLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(WebVerifiableHistoryCreator.builder(new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem"))))
                    .authentications(TEST_AUTHENTICATIONS)
                    .assertionMethods(TEST_ASSERTION_METHODS)
                    .build()
                    .createDidLog(identifierRegistryUrl)); // MUT
        });

        assertDidLogEntry(didLogEntry.get());

        var params = JsonParser.parseString(didLogEntry.get()).getAsJsonObject().get("parameters").getAsJsonObject();
        assertFalse(params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().isEmpty());
        assertEquals(2, params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().size()); // Effectively, it is only 2 distinct keys
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (multiple updateKeys) with activated prerotation")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    void testCreateDidLogWithMultipleUpdateKeysAndActivatedPrerotation(URL identifierRegistryUrl) throws UpdateKeysDidMethodParameterException, NextKeyHashesDidMethodParameterException {

        AtomicReference<String> didLogEntry = new AtomicReference<>();

        assertDoesNotThrow(() -> {
            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(WebVerifiableHistoryCreator.builder(new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem"))))
                    .nextKeyHashesDidMethodParameter(Set.of(NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public01.pem")))) // activate prerotation by adding one of the 'updateKeys'
                    .authentications(TEST_AUTHENTICATIONS)
                    .assertionMethods(TEST_ASSERTION_METHODS)
                    .build()
                    .createDidLog(identifierRegistryUrl)); // MUT
        });

        assertDidLogEntry(didLogEntry.get());

        var params = JsonParser.parseString(didLogEntry.get()).getAsJsonObject().get("parameters").getAsJsonObject();
        assertFalse(params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().isEmpty());
        assertEquals(2, params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().size()); // Effectively, it is only 2 distinct keys...
        assertFalse(params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().isEmpty());
        assertEquals(1, params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().size());
        var updateKeys = params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().asList().stream().map(JsonElement::getAsString).toList();
        assertTrue(updateKeys.contains(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem")).getUpdateKey()));
        assertEquals(NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public01.pem")).getNextKeyHash(), params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().get(0).getAsString());
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (multiple updateKeys) with activated prerotation")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    void testCreateDidLogWithMultipleUpdateKeysAndActivatedPrerotation2(URL identifierRegistryUrl) {
        // Now, try activating prerotation by adding a hash of whole another key to be used in the future
        AtomicReference<String> didLogEntry = new AtomicReference<>();

        assertDoesNotThrow(() -> {
            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(WebVerifiableHistoryCreator.builder(new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem"))))
                    .nextKeyHashesDidMethodParameter(Set.of(NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public01.pem")))) // activate prerotation by adding another key for the future
                    .authentications(TEST_AUTHENTICATIONS)
                    .assertionMethods(TEST_ASSERTION_METHODS)
                    .build()
                    .createDidLog(identifierRegistryUrl)); // MUT
        });

        assertDidLogEntry(didLogEntry.get());

        var params = JsonParser.parseString(didLogEntry.get()).getAsJsonObject().get("parameters").getAsJsonObject();
        assertFalse(params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().isEmpty());
        assertEquals(2, params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().size()); // Effectively, it is only 2 distinct keys...
        assertFalse(params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().isEmpty());
        assertEquals(1, params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().size());
        assertNotEquals(NextKeyHashesDidMethodParameter.of(params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().get(1).getAsString()).getNextKeyHash(),
                params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().get(0).getAsString()); // MUST NOT match the last added updateKey
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (multiple updateKeys) with activated prerotation")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    void testCreateDidLogWithMultipleUpdateKeysAndActivatedPrerotation3(URL identifierRegistryUrl) throws UpdateKeysDidMethodParameterException, NextKeyHashesDidMethodParameterException {
        // Now, try activating prerotation by adding a hash of whole another key to be used in the future
        AtomicReference<String> didLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(WebVerifiableHistoryCreator.builder(TEST_CRYPTO_SUITE_JKS)
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem")))) // it matches the signing key, thus it should not be added to 'updateKeys'
                    .nextKeyHashesDidMethodParameter(Set.of(NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public01.pem")))) // activate prerotation by adding one of the 'updateKeys'
                    .authentications(TEST_AUTHENTICATIONS)
                    .assertionMethods(TEST_ASSERTION_METHODS)
                    .build()
                    .createDidLog(identifierRegistryUrl)); // MUT
        });

        assertDidLogEntry(didLogEntry.get());

        var params = JsonParser.parseString(didLogEntry.get()).getAsJsonObject().get("parameters").getAsJsonObject();
        assertFalse(params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().isEmpty());
        assertEquals(1, params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().size()); // Effectively, it is one single keys...
        assertFalse(params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().isEmpty());
        assertEquals(1, params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().size());
        assertEquals(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem")).getUpdateKey(), params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().get(0).getAsString());
        assertEquals(NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public01.pem")).getNextKeyHash(), params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().get(0).getAsString());
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants using Java Keystore (JKS)")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    void testCreateDidLogUsingJKS(URL identifierRegistryUrl) {
        AtomicReference<String> didLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            didLogEntry.set(WebVerifiableHistoryCreator.builder(TEST_CRYPTO_SUITE_JKS)
                    .authentications(TEST_AUTHENTICATIONS)
                    .assertionMethods(TEST_ASSERTION_METHODS)
                    .build()
                    .createDidLog(identifierRegistryUrl)); // MUT
        });

        assertDidLogEntry(didLogEntry.get());

        var didDoc = JsonParser.parseString(didLogEntry.get()).getAsJsonObject().get("state").getAsJsonObject();
        assertTrue(didDoc.get("authentication").isJsonArray());
        var authentication = didDoc.get("authentication").getAsJsonArray();
        assertTrue(authentication.get(0).getAsString().endsWith("#my-auth-key-01"));
        assertTrue(didDoc.get("assertionMethod").isJsonArray());
        var assertionMethod = didDoc.get("assertionMethod").getAsJsonArray();
        assertTrue(assertionMethod.get(0).getAsString().endsWith("#my-assert-key-01"));
        assertTrue(didDoc.get("verificationMethod").isJsonArray());
        var verificationMethod = didDoc.get("verificationMethod").getAsJsonArray();
        assertTrue(verificationMethod.get(0).getAsJsonObject().get("id").getAsString().endsWith("my-auth-key-01"));
        assertTrue(verificationMethod.get(1).getAsJsonObject().get("id").getAsString().endsWith("my-assert-key-01"));
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (incl. external authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    void testCreateDidLogUsingJksWithExternalVerificationMethodKeys(URL identifierRegistryUrl) { // https://www.w3.org/TR/did-core/#assertion
        AtomicReference<String> didLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            didLogEntry.set(WebVerifiableHistoryCreator.builder(TEST_CRYPTO_SUITE_JKS)
                    .assertionMethods(TEST_ASSERTION_METHODS)
                    .authentications(TEST_AUTHENTICATIONS)
                    .build()
                    // CAUTION datetime is set explicitly here just to be able to get a deterministic output
                    .createDidLog(identifierRegistryUrl, ZonedDateTime.parse("2012-12-12T12:12:12Z"))); // MUT
        });

        assertDidLogEntry(didLogEntry.get());

        var didDoc = JsonParser.parseString(didLogEntry.get()).getAsJsonObject().get("state").getAsJsonObject();
        assertTrue(didDoc.get("authentication").isJsonArray());
        var authentication = didDoc.get("authentication").getAsJsonArray();
        assertTrue(authentication.get(0).getAsString().endsWith("#my-auth-key-01"));
        assertTrue(didDoc.get("assertionMethod").isJsonArray());
        var assertionMethod = didDoc.get("assertionMethod").getAsJsonArray();
        assertTrue(assertionMethod.get(0).getAsString().endsWith("#my-assert-key-01"));
        assertTrue(didDoc.get("verificationMethod").isJsonArray());
        var verificationMethod = didDoc.get("verificationMethod").getAsJsonArray();
        assertTrue(verificationMethod.get(0).getAsJsonObject().get("id").getAsString().endsWith("#my-auth-key-01"));
        assertTrue(verificationMethod.get(1).getAsJsonObject().get("id").getAsString().endsWith("#my-assert-key-01"));

        assertTrue("""
                {"versionId":"1-QmdFbTY7oG4JeMvF3xMu5TurE1YEG5HtZcmDWJz6HjPh7b","versionTime":"2012-12-12T12:12:12Z","parameters":{"method":"did:webvh:1.0","scid":"QmcdhxoCTGiRN6g3TJvT2iWwpeZrT43y93XZvKVEtvhNs7","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},"state":{"id":"did:webvh:QmcdhxoCTGiRN6g3TJvT2iWwpeZrT43y93XZvKVEtvhNs7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","profile_version":"swiss-profile-anchor:1.0.0","authentication":["did:webvh:QmcdhxoCTGiRN6g3TJvT2iWwpeZrT43y93XZvKVEtvhNs7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:webvh:QmcdhxoCTGiRN6g3TJvT2iWwpeZrT43y93XZvKVEtvhNs7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmcdhxoCTGiRN6g3TJvT2iWwpeZrT43y93XZvKVEtvhNs7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","controller":"did:webvh:QmcdhxoCTGiRN6g3TJvT2iWwpeZrT43y93XZvKVEtvhNs7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:webvh:QmcdhxoCTGiRN6g3TJvT2iWwpeZrT43y93XZvKVEtvhNs7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","controller":"did:webvh:QmcdhxoCTGiRN6g3TJvT2iWwpeZrT43y93XZvKVEtvhNs7:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"assertionMethod","proofValue":"z4Fw8t6e6m5THuPyWmY1shAUKonoVgUzbGFLareXfeLc8drNVJe6AiwbdLXJRVSSTJbTQVsgKcYSt7g7skHENuXtp"}]}
                """.contains(didLogEntry.get()));
    }

    @DisplayName("Building DID log entry without cryptographic suite (or verification material) throws IncompleteDidLogEntryBuilderException")
    @Test
    void testCreateDidLogWithoutCryptographicSuiteThrowsIncompleteDidLogEntryBuilderException() {
        var exc = assertThrowsExactly(IncompleteDidLogEntryBuilderException.class, () -> {
            // IMPORTANT null is provided intentionally (no cryptographic suite supplied)
            WebVerifiableHistoryCreator.builder(null)
                    .authentications(TEST_AUTHENTICATIONS)
                    .assertionMethods(TEST_ASSERTION_METHODS)
                    .build()
                    .createDidLog(URL.of(new URI(TEST_DID_URL), null)); // MUT
        });
        assertTrue(exc.getMessage().contains("No cryptographic suite supplied"));

        exc = assertThrowsExactly(IncompleteDidLogEntryBuilderException.class, () -> {
            // the signing key are generated on-the-fly
            WebVerifiableHistoryCreator.builder(new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                    // IMPORTANT Both .authenticationKeys() and .authenticationKeys() calls are omitted intentionally (no verification material supplied)
                    .build()
                    .createDidLog(URL.of(new URI(TEST_DID_URL), null)); // MUT
        });
        assertTrue(exc.getMessage().contains("No verification material"));
    }

    @DisplayName("Trying to build a DID log entry with same update key and next key hash, should throw DidLogUpdaterStrategyException")
    @Test
    void testCreateDidLogWithSameUpdateAndRotationKeyExpectingException() {
        var e = assertThrowsExactly(DidLogCreatorStrategyException.class, () -> {
            WebVerifiableHistoryCreator.builder(TEST_CRYPTO_SUITE)
                    .authentications(TEST_AUTHENTICATIONS)
                    .assertionMethods(TEST_ASSERTION_METHODS)
                    .updateKeysDidMethodParameter(Set.of(
                            UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem"))
                    ))
                    .nextKeyHashesDidMethodParameter(Set.of(
                            NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public01.pem")),
                            NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public.pem"))
                    ))
                    .build().createDidLog(URL.of(new URI(TEST_DID_URL), null));
        });
        assertTrue(e.getMessage().contains("not allowed to be in both"));
    }

    @DisplayName("Building did:webvh log entry from an existing DID document")
    @Test
    void testFromDidDoc() {
        var zdt = ZonedDateTime.now();
        assertDoesNotThrow(() -> {
            var url = identifierRegistryUrl().stream().toList();
            var tdwUrl = url.getFirst();
            var webvhUrl = url.getLast();

            var didDoc = ch.admin.bj.swiyu.didtoolbox.model.TdwDidLogMetaPeeker.peek(
                            DidLogCreatorContext.builder(DidMethodEnum.TDW_0_3, new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                                    //.updateKeys(Set.of(new File("src/test/data/public.pem")))
                                    .assertionMethods(TEST_ASSERTION_METHODS)
                                    .authentications(TEST_AUTHENTICATIONS)
                                    .build()
                                    .create(tdwUrl)
                    )
                    .getDidDoc();

            var didLogEntry = WebVerifiableHistoryCreator.createDidLogFromDidDoc(new EdDsaJcs2022VcDataIntegrityCryptographicSuite(), didDoc, webvhUrl, zdt);

            assertNotNull(didLogEntry);
            assertTrue(JsonParser.parseString(didLogEntry).isJsonObject());
            var jsonObject = JsonParser.parseString(didLogEntry).getAsJsonObject();
            var didWebvhDoc = jsonObject.get("state").getAsJsonObject();

            var didTdwDoc = JsonParser.parseString(didDoc.toJson()).getAsJsonObject();

            assertTrue(didWebvhDoc.asMap().keySet().containsAll(didTdwDoc.asMap().keySet()));
            assertTrue(didWebvhDoc.has("profile_version"));
            assertEquals(didTdwDoc.size(), didWebvhDoc.size() - 1); // only difference is profile version
        });
    }
}
