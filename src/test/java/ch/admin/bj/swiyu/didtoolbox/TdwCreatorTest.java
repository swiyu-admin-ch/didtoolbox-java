package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
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

public class TdwCreatorTest {

    final private static VerificationMethodKeyProvider VERIFICATION_METHOD_KEY_PROVIDER;
    final private static VerificationMethodKeyProvider VERIFICATION_METHOD_KEY_PROVIDER_JKS;

    static {
        try {
            VERIFICATION_METHOD_KEY_PROVIDER = new Ed25519VerificationMethodKeyProviderImpl(
                    new FileReader("src/test/data/private.pem"),
                    new FileReader("src/test/data/public.pem"));
            // Total 3 (PrivateKeyEntry) entries available in the JKS: myalias/myalias2/myalias3
            VERIFICATION_METHOD_KEY_PROVIDER_JKS = new Ed25519VerificationMethodKeyProviderImpl(
                    new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias", "changeit");
        } catch (Exception intolerable) {
            throw new RuntimeException(intolerable);
        }
    }

    private static void assertDidLogEntry(String didLogEntry) {

        assertNotNull(didLogEntry);
        assertTrue(JsonParser.parseString(didLogEntry).isJsonArray());
        JsonArray jsonArray = JsonParser.parseString(didLogEntry).getAsJsonArray();

        assertTrue(jsonArray.get(2).isJsonObject());
        var params = jsonArray.get(2).getAsJsonObject();
        assertTrue(params.has("method"));
        assertTrue(params.has("scid"));
        assertTrue(params.has("updateKeys"));
        assertTrue(params.get("updateKeys").isJsonArray());

        assertTrue(jsonArray.get(3).isJsonObject());
        assertTrue(jsonArray.get(3).getAsJsonObject().has("value"));
        var didDoc = jsonArray.get(3).getAsJsonObject().get("value").getAsJsonObject();
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

        var proofs = jsonArray.get(4);
        assertTrue(proofs.isJsonArray());
        assertFalse(proofs.getAsJsonArray().isEmpty());
        var proof = proofs.getAsJsonArray().get(0);
        assertTrue(proof.isJsonObject());
        assertTrue(proof.getAsJsonObject().has("proofValue"));
    }

    private static Collection<URL> identifierRegistryUrl() throws URISyntaxException, MalformedURLException {
        return Arrays.asList(
                URL.of(new URI("https://127.0.0.1:54858"), null),
                URL.of(new URI("https://127.0.0.1:54858/123456789"), null),
                URL.of(new URI("https://127.0.0.1:54858/123456789/123456789/did.jsonl"), null)
        );
    }

    @DisplayName("Building TDW log entry for various identifierRegistryUrl variants")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testCreate(URL identifierRegistryUrl) {

        String didLogEntry = null;
        try {

            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry = TdwCreator.builder()
                    // the default signer (verificationMethodKeyProvider) is used
                    .forceOverwrite(true)
                    .build()
                    .create(identifierRegistryUrl); // MUT

        } catch (IOException e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);
    }

    @DisplayName("Building TDW log entry for various identifierRegistryUrl variants (multiple updateKeys)")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testCreateWithMultipleUpdateKeys(URL identifierRegistryUrl) {

        String didLogEntry = null;
        try {

            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry = TdwCreator.builder()
                    // the default signer (verificationMethodKeyProvider) is used
                    .updateKeys(Set.of(new File("src/test/data/public.pem")))
                    .forceOverwrite(true)
                    .build()
                    .create(identifierRegistryUrl); // MUT

        } catch (IOException e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);

        var params = JsonParser.parseString(didLogEntry).getAsJsonArray().get(2).getAsJsonObject();
        assertFalse(params.get("updateKeys").getAsJsonArray().isEmpty());
        assertEquals(2, params.get("updateKeys").getAsJsonArray().size());// Effectively, it is only 2 distinct keys
    }

    @DisplayName("Building TDW log entry for various identifierRegistryUrl variants using Java Keystore (JKS)")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJKS(URL identifierRegistryUrl) {

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS)
                    .forceOverwrite(true)
                    .build()
                    .create(identifierRegistryUrl); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);

        var didDoc = JsonParser.parseString(didLogEntry).getAsJsonArray().get(3).getAsJsonObject().get("value").getAsJsonObject();
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

    @DisplayName("Building TDW log entry for various identifierRegistryUrl variants (incl. external authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJksWithExternalVerificationMethodKeys(URL identifierRegistryUrl) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
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

        var didDoc = JsonParser.parseString(didLogEntry).getAsJsonArray().get(3).getAsJsonObject().get("value").getAsJsonObject();
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
                ["1-QmSeMFxj3JeYJAStVUWoHqfJiETJEgqiT56oao2FtigF8f","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmQNJb1SN9Z4EkqTkRLb3ZfkWWgRuSsJegkoSSnDLnbWoS","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmQNJb1SN9Z4EkqTkRLb3ZfkWWgRuSsJegkoSSnDLnbWoS:127.0.0.1%3A54858","authentication":["did:tdw:QmQNJb1SN9Z4EkqTkRLb3ZfkWWgRuSsJegkoSSnDLnbWoS:127.0.0.1%3A54858#my-auth-key-01"],"assertionMethod":["did:tdw:QmQNJb1SN9Z4EkqTkRLb3ZfkWWgRuSsJegkoSSnDLnbWoS:127.0.0.1%3A54858#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmQNJb1SN9Z4EkqTkRLb3ZfkWWgRuSsJegkoSSnDLnbWoS:127.0.0.1%3A54858#my-auth-key-01","controller":"did:tdw:QmQNJb1SN9Z4EkqTkRLb3ZfkWWgRuSsJegkoSSnDLnbWoS:127.0.0.1%3A54858","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmQNJb1SN9Z4EkqTkRLb3ZfkWWgRuSsJegkoSSnDLnbWoS:127.0.0.1%3A54858#my-assert-key-01","controller":"did:tdw:QmQNJb1SN9Z4EkqTkRLb3ZfkWWgRuSsJegkoSSnDLnbWoS:127.0.0.1%3A54858","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmSeMFxj3JeYJAStVUWoHqfJiETJEgqiT56oao2FtigF8f","proofValue":"z5ZDwr9eC5wa2Zyvr2kZWFQXMxLRBHXzLdD57aCHpPTZDncCDL4BTMus7bzDe6z95KwQPytyGgst5eDE2GQ7ee9yS"}]]
                ["1-QmaSTRGw9KGdfcvHuatHgJmU39PVAst8sc7tqoZHGDH8u8","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmNrXVpbXdRiouHuBiwc3QBr3Fv4euQZZq57Yjhor3bwDD","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmNrXVpbXdRiouHuBiwc3QBr3Fv4euQZZq57Yjhor3bwDD:127.0.0.1%3A54858:123456789","authentication":["did:tdw:QmNrXVpbXdRiouHuBiwc3QBr3Fv4euQZZq57Yjhor3bwDD:127.0.0.1%3A54858:123456789#my-auth-key-01"],"assertionMethod":["did:tdw:QmNrXVpbXdRiouHuBiwc3QBr3Fv4euQZZq57Yjhor3bwDD:127.0.0.1%3A54858:123456789#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmNrXVpbXdRiouHuBiwc3QBr3Fv4euQZZq57Yjhor3bwDD:127.0.0.1%3A54858:123456789#my-auth-key-01","controller":"did:tdw:QmNrXVpbXdRiouHuBiwc3QBr3Fv4euQZZq57Yjhor3bwDD:127.0.0.1%3A54858:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmNrXVpbXdRiouHuBiwc3QBr3Fv4euQZZq57Yjhor3bwDD:127.0.0.1%3A54858:123456789#my-assert-key-01","controller":"did:tdw:QmNrXVpbXdRiouHuBiwc3QBr3Fv4euQZZq57Yjhor3bwDD:127.0.0.1%3A54858:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmaSTRGw9KGdfcvHuatHgJmU39PVAst8sc7tqoZHGDH8u8","proofValue":"z3VNi39GyPsS7osrVmCidAhGpj8Zrmg9aj7CbnJQdMvYFEmRgV1LWKmdAsDK4kv3fNrFepXki1sA695pswqoFxAoc"}]]
                ["1-QmSoDKszWCWt6uwJtmNLoqxS1gnCfaRfnNtLB3pR2Fh1QH","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmV8SsSXMBZNT4z2oDztdCaPPxwL6tmKNdFZFDJA2vtYnA","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmV8SsSXMBZNT4z2oDztdCaPPxwL6tmKNdFZFDJA2vtYnA:127.0.0.1%3A54858:123456789:123456789","authentication":["did:tdw:QmV8SsSXMBZNT4z2oDztdCaPPxwL6tmKNdFZFDJA2vtYnA:127.0.0.1%3A54858:123456789:123456789#my-auth-key-01"],"assertionMethod":["did:tdw:QmV8SsSXMBZNT4z2oDztdCaPPxwL6tmKNdFZFDJA2vtYnA:127.0.0.1%3A54858:123456789:123456789#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmV8SsSXMBZNT4z2oDztdCaPPxwL6tmKNdFZFDJA2vtYnA:127.0.0.1%3A54858:123456789:123456789#my-auth-key-01","controller":"did:tdw:QmV8SsSXMBZNT4z2oDztdCaPPxwL6tmKNdFZFDJA2vtYnA:127.0.0.1%3A54858:123456789:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmV8SsSXMBZNT4z2oDztdCaPPxwL6tmKNdFZFDJA2vtYnA:127.0.0.1%3A54858:123456789:123456789#my-assert-key-01","controller":"did:tdw:QmV8SsSXMBZNT4z2oDztdCaPPxwL6tmKNdFZFDJA2vtYnA:127.0.0.1%3A54858:123456789:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmSoDKszWCWt6uwJtmNLoqxS1gnCfaRfnNtLB3pR2Fh1QH","proofValue":"z3r67y4jDoyzmEY86bZTcShmpgiCLX9xPr3roAeDcWpfGv2DddNDvjJAtjmqQDWWz9apjkpoaB7Hn4uq6e8MhGhbW"}]]
                """.contains(didLogEntry));
    }

    @DisplayName("Building TDW log entry for various identifierRegistryUrl variants (incl. generated authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJksWithGeneratedVerificationMethodKeys(URL identifierRegistryUrl) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .verificationMethodKeyProvider(VERIFICATION_METHOD_KEY_PROVIDER_JKS)
                    .assertionMethodKeys(Map.of("my-assert-key-01", ""))
                    .authenticationKeys(Map.of("my-auth-key-01", ""))
                    .build()
                    .create(identifierRegistryUrl); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);

        var didDoc = JsonParser.parseString(didLogEntry).getAsJsonArray().get(3).getAsJsonObject().get("value").getAsJsonObject();
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

    @DisplayName("Building TDW log entry for various identifierRegistryUrl variants (incl. generated authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJksWithPartiallyGeneratedVerificationMethodKeys(URL identifierRegistryUrl) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
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

        var didDoc = JsonParser.parseString(didLogEntry).getAsJsonArray().get(3).getAsJsonObject().get("value").getAsJsonObject();
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


    @DisplayName("Building TDW log entry for various identifierRegistryUrl variants (incl. generated authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJksWithPartiallyGeneratedVerificationMethodKeys2(URL identifierRegistryUrl) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
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

        var didDoc = JsonParser.parseString(didLogEntry).getAsJsonArray().get(3).getAsJsonObject().get("value").getAsJsonObject();
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
