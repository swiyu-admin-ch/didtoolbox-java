package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class WebVerifiableHistoryCreatorTest extends AbstractUtilTestBase {

    private static void assertDidLogEntry(String didLogEntry) {

        assertNotNull(didLogEntry);
        assertTrue(JsonParser.parseString(didLogEntry).isJsonObject());
        var jsonObject = JsonParser.parseString(didLogEntry).getAsJsonObject();

        assertTrue(jsonObject.get("parameters").isJsonObject());
        var params = jsonObject.get("parameters").getAsJsonObject();
        assertTrue(params.has("method"));
        assertTrue(params.has("scid"));
        assertTrue(params.has("updateKeys"));
        assertTrue(params.get("updateKeys").isJsonArray());

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

    private static Collection<URL> identifierRegistryUrl() throws URISyntaxException, MalformedURLException {
        return Arrays.asList(
                URL.of(new URI("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085"), null),
                URL.of(new URI("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085/did.jsonl"), null)
        );
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testCreate(URL identifierRegistryUrl) {

        String didLogEntry = null;
        try {

            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry = WebVerifiableHistoryCreator.builder()
                    // the default signer (verificationMethodKeyProvider) is used
                    .forceOverwrite(true)
                    .build()
                    .create(identifierRegistryUrl); // MUT

        } catch (IOException e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (multiple updateKeys)")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testCreateWithMultipleUpdateKeys(URL identifierRegistryUrl) {

        String didLogEntry = null;
        try {

            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry = WebVerifiableHistoryCreator.builder()
                    // the default signer (verificationMethodKeyProvider) is used
                    .updateKeys(Set.of(new File("src/test/data/public.pem")))
                    .forceOverwrite(true)
                    .build()
                    .create(identifierRegistryUrl); // MUT

        } catch (IOException e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);

        var params = JsonParser.parseString(didLogEntry).getAsJsonObject().get("parameters").getAsJsonObject();
        assertFalse(params.get("updateKeys").getAsJsonArray().isEmpty());
        assertEquals(2, params.get("updateKeys").getAsJsonArray().size());// Effectively, it is only 2 distinct keys
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants using Java Keystore (JKS)")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJKS(URL identifierRegistryUrl) {

        String didLogEntry = null;
        try {

            didLogEntry = WebVerifiableHistoryCreator.builder()
                    .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS)
                    .forceOverwrite(true)
                    .build()
                    .create(identifierRegistryUrl); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);

        var didDoc = JsonParser.parseString(didLogEntry).getAsJsonObject().get("state").getAsJsonObject();
        assertTrue(didDoc.get("authentication").isJsonArray());
        var authentication = didDoc.get("authentication").getAsJsonArray();
        assertTrue(authentication.get(0).getAsString().endsWith("#auth-key-01")); // created by default
        assertTrue(didDoc.get("assertionMethod").isJsonArray());
        var assertionMethod = didDoc.get("assertionMethod").getAsJsonArray();
        assertTrue(assertionMethod.get(0).getAsString().endsWith("#assert-key-01")); // created by default
        assertTrue(didDoc.get("verificationMethod").isJsonArray());
        var verificationMethod = didDoc.get("verificationMethod").getAsJsonArray();
        assertTrue(verificationMethod.get(0).getAsJsonObject().get("id").getAsString().endsWith("auth-key-01")); // created by default
        assertTrue(verificationMethod.get(1).getAsJsonObject().get("id").getAsString().endsWith("assert-key-01")); // created by default

        //System.out.println(didLogEntry);

        //assertTrue("""
        //        """.contains(didLogEntry));
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (incl. external authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJksWithExternalVerificationMethodKeys(URL identifierRegistryUrl) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = WebVerifiableHistoryCreator.builder()
                    .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS)
                    .assertionMethodKeys(Map.of(
                            "my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01")
                    ))
                    .authenticationKeys(Map.of(
                            "my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01")
                    ))
                    .build()
                    // CAUTION datetime is set explicitly here just to be able to run assertTrue("...".contains(didLogEntry));
                    .create(identifierRegistryUrl, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);

        var didDoc = JsonParser.parseString(didLogEntry).getAsJsonObject().get("state").getAsJsonObject();
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

        //System.out.println(didLogEntry);

        assertTrue("""
                {"versionId":"1-QmaCuNToJzcbc2DJKyYrdJCHkfe4Bs8xjxoyNCP5RTjJvZ","versionTime":"2012-12-12T12:12:12Z","parameters":{"method":"did:webvh:1.0","scid":"QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:webvh:QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01"],"assertionMethod":["did:webvh:QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:webvh:QmSPEpPcSwb3fegq8YE8zotcPEgzHrSFyTJJDAzPo2CYBp:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#my-assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"assertionMethod","proofValue":"zaKCwhEC548Aiwa1Uah8pCKtgih4WPbBQEx9BYVSg9vURt293JQnrrKMd4YwXLnZyuNDA8NCvkNxFFndJuuizsj7"}]}
                """.contains(didLogEntry));
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (incl. generated authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJksWithGeneratedVerificationMethodKeys(URL identifierRegistryUrl) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = WebVerifiableHistoryCreator.builder()
                    .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS)
                    .assertionMethodKeys(Map.of("my-assert-key-01", ""))
                    .authenticationKeys(Map.of("my-auth-key-01", ""))
                    .build()
                    .create(identifierRegistryUrl); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);

        var didDoc = JsonParser.parseString(didLogEntry).getAsJsonObject().get("state").getAsJsonObject();
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

        //System.out.println(didLogEntry);

        //assertTrue("""
        //        """.contains(didLogEntry));
    }

    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (incl. generated authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJksWithPartiallyGeneratedVerificationMethodKeys(URL identifierRegistryUrl) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = WebVerifiableHistoryCreator.builder()
                    .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS)
                    .assertionMethodKeys(Map.of("my-assert-key-01", ""))
                    // CAUTION An "authentication" key will be added by default, so need to call method: .authenticationKeys(Map.of("my-auth-key-01", ""))
                    .forceOverwrite(true)
                    .build()
                    .create(identifierRegistryUrl); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);

        var didDoc = JsonParser.parseString(didLogEntry).getAsJsonObject().get("state").getAsJsonObject();
        assertTrue(didDoc.get("authentication").isJsonArray());
        var authentication = didDoc.get("authentication").getAsJsonArray();
        assertTrue(authentication.get(0).getAsString().endsWith("auth-key-01")); // created by default
        assertTrue(didDoc.get("assertionMethod").isJsonArray());
        var assertionMethod = didDoc.get("assertionMethod").getAsJsonArray();
        assertTrue(assertionMethod.get(0).getAsString().endsWith("#my-assert-key-01"));
        assertTrue(didDoc.get("verificationMethod").isJsonArray());
        var verificationMethod = didDoc.get("verificationMethod").getAsJsonArray();
        assertTrue(verificationMethod.get(0).getAsJsonObject().get("id").getAsString().endsWith("auth-key-01")); // created by default
        assertTrue(verificationMethod.get(1).getAsJsonObject().get("id").getAsString().endsWith("my-assert-key-01"));

        //System.out.println(didLogEntry);

        //assertTrue("""
        //        """.contains(didLogEntry));
    }


    @DisplayName("Building did:webvh log entry for various identifierRegistryUrl variants (incl. generated authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJksWithPartiallyGeneratedVerificationMethodKeys2(URL identifierRegistryUrl) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = WebVerifiableHistoryCreator.builder()
                    .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS)
                    // CAUTION An "assertionMethod" key will be added by default, so need to call method: .assertionMethodKeys(Map.of("my-assert-key-01", ""))
                    .authenticationKeys(Map.of("my-auth-key-01", ""))
                    .forceOverwrite(true)
                    .build()
                    .create(identifierRegistryUrl); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);

        var didDoc = JsonParser.parseString(didLogEntry).getAsJsonObject().get("state").getAsJsonObject();
        assertTrue(didDoc.get("authentication").isJsonArray());
        var authentication = didDoc.get("authentication").getAsJsonArray();
        assertTrue(authentication.get(0).getAsString().endsWith("my-auth-key-01"));
        assertTrue(didDoc.get("assertionMethod").isJsonArray());
        var assertionMethod = didDoc.get("assertionMethod").getAsJsonArray();
        assertTrue(assertionMethod.get(0).getAsString().endsWith("#assert-key-01")); // created by default
        assertTrue(didDoc.get("verificationMethod").isJsonArray());
        var verificationMethod = didDoc.get("verificationMethod").getAsJsonArray();
        assertTrue(verificationMethod.get(0).getAsJsonObject().get("id").getAsString().endsWith("my-auth-key-01"));
        assertTrue(verificationMethod.get(1).getAsJsonObject().get("id").getAsString().endsWith("assert-key-01")); // created by default

        //System.out.println(didLogEntry);

        //assertTrue("""
        //        """.contains(didLogEntry));
    }
}
