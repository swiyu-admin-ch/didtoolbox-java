package ch.admin.bj.swiyu.didtoolbox.webvh;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.JCSHasher;
import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.model.NamedDidMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.model.UpdateKeysDidMethodParameter;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URL;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.Map;
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
    public void testCreateDidLog(URL identifierRegistryUrl) {

        AtomicReference<String> didLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {

            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(WebVerifiableHistoryCreator.builder()
                    // the default signer (verificationMethodKeyProvider) is used
                    .forceOverwrite(true)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .build()
                    .createDidLog(identifierRegistryUrl)); // MUT
        });

        assertDidLogEntry(didLogEntry.get());
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (multiple updateKeys)")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testCreateDidLogWithMultipleUpdateKeys(URL identifierRegistryUrl) {

        AtomicReference<String> didLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(WebVerifiableHistoryCreator.builder()
                    // the default signer (verificationMethodKeyProvider) is used
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem"))))
                    .forceOverwrite(true)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
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
    public void testCreateDidLogWithMultipleUpdateKeysAndActivatedPrerotation(URL identifierRegistryUrl) {

        AtomicReference<String> didLogEntry = new AtomicReference<>();

        assertDoesNotThrow(() -> {
            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(WebVerifiableHistoryCreator.builder()
                    // the default signer (verificationMethodKeyProvider) is used
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem"))))
                    .nextKeyHashesDidMethodParameter(Set.of(NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public.pem")))) // activate prerotation by adding one of the 'updateKeys'
                    .forceOverwrite(true)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .build()
                    .createDidLog(identifierRegistryUrl)); // MUT
        });

        assertDidLogEntry(didLogEntry.get());

        var params = JsonParser.parseString(didLogEntry.get()).getAsJsonObject().get("parameters").getAsJsonObject();
        assertFalse(params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().isEmpty());
        assertEquals(2, params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().size()); // Effectively, it is only 2 distinct keys...
        assertFalse(params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().isEmpty());
        assertEquals(1, params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().size());
        assertEquals(NextKeyHashesDidMethodParameter.of(params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().get(1).getAsString()).getNextKeyHash(),
                params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().get(0).getAsString()); // MUST match the last added updateKey
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (multiple updateKeys) with activated prerotation")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testCreateDidLogWithMultipleUpdateKeysAndActivatedPrerotation2(URL identifierRegistryUrl) {

        // Now, try activating prerotation by adding a hash of whole another key to be used in the future

        AtomicReference<String> didLogEntry = new AtomicReference<>();

        assertDoesNotThrow(() -> {
            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(WebVerifiableHistoryCreator.builder()
                    // the default signer (verificationMethodKeyProvider) is used
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem"))))
                    .nextKeyHashesDidMethodParameter(Set.of(NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public01.pem")))) // activate prerotation by adding another key for the future
                    .forceOverwrite(true)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
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
    public void testCreateDidLogWithMultipleUpdateKeysAndActivatedPrerotation3(URL identifierRegistryUrl) {

        // Now, try activating prerotation by adding a hash of whole another key to be used in the future

        AtomicReference<String> didLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(WebVerifiableHistoryCreator.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE_JKS)
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem")))) // it matches the signing key, thus it should not be added to 'updateKeys'
                    .nextKeyHashesDidMethodParameter(Set.of(NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public.pem")))) // activate prerotation by adding one of the 'updateKeys'
                    .forceOverwrite(true)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .build()
                    .createDidLog(identifierRegistryUrl)); // MUT
        });

        assertDidLogEntry(didLogEntry.get());

        var params = JsonParser.parseString(didLogEntry.get()).getAsJsonObject().get("parameters").getAsJsonObject();
        assertFalse(params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().isEmpty());
        assertEquals(1, params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().size()); // Effectively, it is one single keys...
        assertFalse(params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().isEmpty());
        assertEquals(1, params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().size());
        assertEquals(NextKeyHashesDidMethodParameter.of(params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().get(0).getAsString()).getNextKeyHash(),
                params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().get(0).getAsString()); // MUST match the last added (in this case, the only) updateKey
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants using Java Keystore (JKS)")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testCreateDidLogUsingJKS(URL identifierRegistryUrl) {

        AtomicReference<String> didLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            didLogEntry.set(WebVerifiableHistoryCreator.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE_JKS)
                    .forceOverwrite(true)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
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
    public void testCreateDidLogUsingJksWithExternalVerificationMethodKeys(URL identifierRegistryUrl) { // https://www.w3.org/TR/did-core/#assertion

        AtomicReference<String> didLogEntry = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            didLogEntry.set(WebVerifiableHistoryCreator.builder()
                    .cryptographicSuite(TEST_CRYPTO_SUITE_JKS)
                    .assertionMethodKeys(Map.of(
                            "my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/assert-key-01.pub"), "my-assert-key-01")
                    ))
                    .authenticationKeys(Map.of(
                            "my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/auth-key-01.pub"), "my-auth-key-01")
                    ))
                    .build()
                    // CAUTION datetime is set explicitly here just to be able to run assertTrue("...".contains(didLogEntry));
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
                {"versionId":"1-QmaCuNToJzcbc2DJKyYrdJCHkfe4Bs8xjxoyNCP5RTjJvZ","versionTime":"2012-12-12T12:12:12Z","parameters":{"method":"did:webvh:1.0","scid":"QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:webvh:QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:webvh:QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:webvh:QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"assertionMethod","proofValue":"zaKCwhEC548Aiwa1Uah8pCKtgih4WPbBQEx9BYVSg9vURt293JQnrrKMd4YwXLnZyuNDA8NCvkNxFFndJuuizsj7"}]}
                """.contains(didLogEntry.get()));
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
                            DidLogCreatorContext.builder()
                                    .didMethod(DidMethodEnum.TDW_0_3)
                                    // the default signer (verificationMethodKeyProvider) is used
                                    //.updateKeys(Set.of(new File("src/test/data/public.pem")))
                                    .forceOverwrite(true)
                                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                                    .build()
                                    .create(tdwUrl)
                    )
                    .getDidDoc();

            assertDidLogEntry(
                    WebVerifiableHistoryCreator
                            .createDidLogFromDidDoc(didDoc, webvhUrl, zdt) // MUT
            );
        });
    }
}
