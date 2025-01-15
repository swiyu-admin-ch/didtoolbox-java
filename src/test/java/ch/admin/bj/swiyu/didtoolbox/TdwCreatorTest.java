package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class TdwCreatorTest {

    private static void assertDidLogEntry(String didLogEntry) {

        assertNotNull(didLogEntry);
        assertTrue(JsonParser.parseString(didLogEntry).isJsonArray());
        JsonArray jsonArray = JsonParser.parseString(didLogEntry).getAsJsonArray();

        assertTrue(jsonArray.get(2).isJsonObject());
        var params = jsonArray.get(2).getAsJsonObject();
        assertTrue(params.has("scid"));
        assertTrue(params.has("updateKeys"));

        assertTrue(jsonArray.get(3).isJsonObject());
        assertTrue(jsonArray.get(3).getAsJsonObject().has("value"));
        var didDoc = jsonArray.get(3).getAsJsonObject().get("value").getAsJsonObject();
        assertTrue(didDoc.has("id"));
        assertTrue(didDoc.has("authentication"));
        assertTrue(didDoc.has("assertionMethod"));
        assertTrue(didDoc.has("verificationMethod"));
        assertTrue(didDoc.get("verificationMethod").isJsonArray());

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

        var creator = TdwCreator.builder();

        String didLogEntry = null;
        try {

            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry = TdwCreator.builder()
                    //.signer(new Ed25519SignerVerifier()) // is the default signer anyway
                    .build()
                    .create(identifierRegistryUrl); // MUT

        } catch (IOException e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);
    }

    @DisplayName("Building TDW log entry for various identifierRegistryUrl variants using Java Keystore (JKS)")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJKS(URL identifierRegistryUrl) {

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .build()
                    .create(identifierRegistryUrl, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);
        JsonArray jsonArray = JsonParser.parseString(didLogEntry).getAsJsonArray();
        var didDoc = jsonArray.get(3).getAsJsonObject().get("value").getAsJsonObject();
        assertTrue(didDoc.get("authentication").getAsJsonArray().get(0).getAsString().endsWith("#auth-key-01"));
        assertTrue(didDoc.get("assertionMethod").getAsJsonArray().get(0).getAsString().endsWith("#assert-key-01"));
        assertTrue(didDoc.get("verificationMethod").getAsJsonArray().get(0).getAsJsonObject().get("id").getAsString().endsWith("auth-key-01"));
        assertTrue(didDoc.get("verificationMethod").getAsJsonArray().get(1).getAsJsonObject().get("id").getAsString().endsWith("assert-key-01"));

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
                    .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .assertionMethodKeys(Map.of(
                            "my-assert-key-01", JwkUtils.loadPublicJWKasJSON(new File("src/test/data/myjsonwebkeys.json"), "my-assert-key-01")
                    ))
                    .authenticationKeys(Map.of(
                            "my-auth-key-01", JwkUtils.loadPublicJWKasJSON(new File("src/test/data/myjsonwebkeys.json"), "my-auth-key-01")
                    ))
                    .build()
                    .create(identifierRegistryUrl, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);
        JsonArray jsonArray = JsonParser.parseString(didLogEntry).getAsJsonArray();
        var didDoc = jsonArray.get(3).getAsJsonObject().get("value").getAsJsonObject();
        assertTrue(didDoc.get("authentication").getAsJsonArray().get(0).getAsString().endsWith("#my-auth-key-01"));
        assertTrue(didDoc.get("assertionMethod").getAsJsonArray().get(0).getAsString().endsWith("#my-assert-key-01"));
        assertTrue(didDoc.get("verificationMethod").getAsJsonArray().get(0).getAsJsonObject().get("id").getAsString().endsWith("my-auth-key-01"));
        assertTrue(didDoc.get("verificationMethod").getAsJsonArray().get(1).getAsJsonObject().get("id").getAsString().endsWith("my-assert-key-01"));

        //System.out.println(didLogEntry);

        assertTrue("""
                ["1-QmNhAFujLeYdxbyYivdFmBAegisv83dCmZ9m2qeqP1ocQH","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmcrvM4Cn9h2xKfg72vNZrfc6CBNHzGXfYaMbCH2Ct5PcR","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:QmcrvM4Cn9h2xKfg72vNZrfc6CBNHzGXfYaMbCH2Ct5PcR:127.0.0.1%3A54858","authentication":["did:tdw:QmcrvM4Cn9h2xKfg72vNZrfc6CBNHzGXfYaMbCH2Ct5PcR:127.0.0.1%3A54858#my-auth-key-01"],"assertionMethod":["did:tdw:QmcrvM4Cn9h2xKfg72vNZrfc6CBNHzGXfYaMbCH2Ct5PcR:127.0.0.1%3A54858#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmcrvM4Cn9h2xKfg72vNZrfc6CBNHzGXfYaMbCH2Ct5PcR:127.0.0.1%3A54858#my-auth-key-01","controller":"did:tdw:QmcrvM4Cn9h2xKfg72vNZrfc6CBNHzGXfYaMbCH2Ct5PcR:127.0.0.1%3A54858","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"NNkYapGrhRxe_GBOBtF2zLyuDqYPefvJAnmbZIi3Srg","y":"Ee9y-aYqlPdxdJHxqAgznxrplJksL5m7KFMTopBN2Kk"}},{"id":"did:tdw:QmcrvM4Cn9h2xKfg72vNZrfc6CBNHzGXfYaMbCH2Ct5PcR:127.0.0.1%3A54858#my-assert-key-01","controller":"did:tdw:QmcrvM4Cn9h2xKfg72vNZrfc6CBNHzGXfYaMbCH2Ct5PcR:127.0.0.1%3A54858","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"eV4ZGw8GUtKOI4mpH5O1cxc_oPJRtbL-u8UzJbtSEHQ","y":"QaNew9zIW6En53YPU4z1FskhdrmTsRPvSO8BUiIaKLY"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmNhAFujLeYdxbyYivdFmBAegisv83dCmZ9m2qeqP1ocQH","proofValue":"z3hKjSQbjKv1gSmjZJ18LsDdRk9Z7ctSBu2vTMRAzmrhvVpqcE5a8aeQS7zoqHtU7soikLj9U2iUfAX8rRS3crpcc"}]]
                ["1-QmVipoV8K5fPQA7QRFuW6GmaBAMoybnVj71QJieNoVLoQP","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmX9t5d2jRPsLBxo9GENc8VeJzoTCwmXv4QP5DJUaBG8o4","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:QmX9t5d2jRPsLBxo9GENc8VeJzoTCwmXv4QP5DJUaBG8o4:127.0.0.1%3A54858:123456789","authentication":["did:tdw:QmX9t5d2jRPsLBxo9GENc8VeJzoTCwmXv4QP5DJUaBG8o4:127.0.0.1%3A54858:123456789#my-auth-key-01"],"assertionMethod":["did:tdw:QmX9t5d2jRPsLBxo9GENc8VeJzoTCwmXv4QP5DJUaBG8o4:127.0.0.1%3A54858:123456789#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmX9t5d2jRPsLBxo9GENc8VeJzoTCwmXv4QP5DJUaBG8o4:127.0.0.1%3A54858:123456789#my-auth-key-01","controller":"did:tdw:QmX9t5d2jRPsLBxo9GENc8VeJzoTCwmXv4QP5DJUaBG8o4:127.0.0.1%3A54858:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"NNkYapGrhRxe_GBOBtF2zLyuDqYPefvJAnmbZIi3Srg","y":"Ee9y-aYqlPdxdJHxqAgznxrplJksL5m7KFMTopBN2Kk"}},{"id":"did:tdw:QmX9t5d2jRPsLBxo9GENc8VeJzoTCwmXv4QP5DJUaBG8o4:127.0.0.1%3A54858:123456789#my-assert-key-01","controller":"did:tdw:QmX9t5d2jRPsLBxo9GENc8VeJzoTCwmXv4QP5DJUaBG8o4:127.0.0.1%3A54858:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"eV4ZGw8GUtKOI4mpH5O1cxc_oPJRtbL-u8UzJbtSEHQ","y":"QaNew9zIW6En53YPU4z1FskhdrmTsRPvSO8BUiIaKLY"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmVipoV8K5fPQA7QRFuW6GmaBAMoybnVj71QJieNoVLoQP","proofValue":"z4qH3SL1Jt7E3hgcFe3RBjZZD53hFt3GXPuTLUh3JwCwV3bGKxDqpLwGRjt9B4GXXSdBgnWUnLZNVGErqbLHKH1aq"}]]
                ["1-QmYxi4r29BxDZyrSHkoP14X7Gr7ug9emh8L6eLowhXAUJu","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmTeeRSQPcfaUDXsZjhjzJDTaez2RSynS2dy5VSBp3aZu4","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:QmTeeRSQPcfaUDXsZjhjzJDTaez2RSynS2dy5VSBp3aZu4:127.0.0.1%3A54858:123456789:123456789","authentication":["did:tdw:QmTeeRSQPcfaUDXsZjhjzJDTaez2RSynS2dy5VSBp3aZu4:127.0.0.1%3A54858:123456789:123456789#my-auth-key-01"],"assertionMethod":["did:tdw:QmTeeRSQPcfaUDXsZjhjzJDTaez2RSynS2dy5VSBp3aZu4:127.0.0.1%3A54858:123456789:123456789#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmTeeRSQPcfaUDXsZjhjzJDTaez2RSynS2dy5VSBp3aZu4:127.0.0.1%3A54858:123456789:123456789#my-auth-key-01","controller":"did:tdw:QmTeeRSQPcfaUDXsZjhjzJDTaez2RSynS2dy5VSBp3aZu4:127.0.0.1%3A54858:123456789:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"NNkYapGrhRxe_GBOBtF2zLyuDqYPefvJAnmbZIi3Srg","y":"Ee9y-aYqlPdxdJHxqAgznxrplJksL5m7KFMTopBN2Kk"}},{"id":"did:tdw:QmTeeRSQPcfaUDXsZjhjzJDTaez2RSynS2dy5VSBp3aZu4:127.0.0.1%3A54858:123456789:123456789#my-assert-key-01","controller":"did:tdw:QmTeeRSQPcfaUDXsZjhjzJDTaez2RSynS2dy5VSBp3aZu4:127.0.0.1%3A54858:123456789:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"eV4ZGw8GUtKOI4mpH5O1cxc_oPJRtbL-u8UzJbtSEHQ","y":"QaNew9zIW6En53YPU4z1FskhdrmTsRPvSO8BUiIaKLY"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmYxi4r29BxDZyrSHkoP14X7Gr7ug9emh8L6eLowhXAUJu","proofValue":"z5xC1AzE1yvteznVnBjKxZau6KwfHDEvAD84ewodRJqverpGF9Vb6RhGVhK5xzXXTjkb8WuGsZxwB1WJkiFSDVm5r"}]]
                """.contains(didLogEntry));
    }

    @DisplayName("Building TDW log entry for various identifierRegistryUrl variants (incl. generated authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testBuildUsingJksWithGeneratedVerificationMethodKeys(URL identifierRegistryUrl) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .assertionMethodKeys(Map.of("my-assert-key-01", ""))
                    .authenticationKeys(Map.of("my-auth-key-01", ""))
                    .build()
                    .create(identifierRegistryUrl, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);
        JsonArray jsonArray = JsonParser.parseString(didLogEntry).getAsJsonArray();
        var didDoc = jsonArray.get(3).getAsJsonObject().get("value").getAsJsonObject();
        assertTrue(didDoc.get("authentication").getAsJsonArray().get(0).getAsString().endsWith("#my-auth-key-01"));
        assertTrue(didDoc.get("assertionMethod").getAsJsonArray().get(0).getAsString().endsWith("#my-assert-key-01"));
        assertTrue(didDoc.get("verificationMethod").getAsJsonArray().get(0).getAsJsonObject().get("id").getAsString().endsWith("my-auth-key-01"));
        assertTrue(didDoc.get("verificationMethod").getAsJsonArray().get(1).getAsJsonObject().get("id").getAsString().endsWith("my-assert-key-01"));

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
                    .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .assertionMethodKeys(Map.of("my-assert-key-01", ""))
                    //.authenticationKeys(Map.of("my-auth-key-01", ""))
                    .build()
                    .create(identifierRegistryUrl, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);
        JsonArray jsonArray = JsonParser.parseString(didLogEntry).getAsJsonArray();
        var didDoc = jsonArray.get(3).getAsJsonObject().get("value").getAsJsonObject();
        assertTrue(didDoc.get("authentication").getAsJsonArray().get(0).getAsString().endsWith("#auth-key-01")); // default
        assertTrue(didDoc.get("assertionMethod").getAsJsonArray().get(0).getAsString().endsWith("#my-assert-key-01"));
        assertTrue(didDoc.get("verificationMethod").getAsJsonArray().get(0).getAsJsonObject().get("id").getAsString().endsWith("auth-key-01")); // default
        assertTrue(didDoc.get("verificationMethod").getAsJsonArray().get(1).getAsJsonObject().get("id").getAsString().endsWith("my-assert-key-01"));

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
                    .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    //.assertionMethodKeys(Map.of("my-assert-key-01", ""))
                    .authenticationKeys(Map.of("my-auth-key-01", ""))
                    .build()
                    .create(identifierRegistryUrl, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);
        JsonArray jsonArray = JsonParser.parseString(didLogEntry).getAsJsonArray();
        var didDoc = jsonArray.get(3).getAsJsonObject().get("value").getAsJsonObject();
        assertTrue(didDoc.get("authentication").getAsJsonArray().get(0).getAsString().endsWith("#my-auth-key-01"));
        assertTrue(didDoc.get("assertionMethod").getAsJsonArray().get(0).getAsString().endsWith("#assert-key-01")); // default
        assertTrue(didDoc.get("verificationMethod").getAsJsonArray().get(0).getAsJsonObject().get("id").getAsString().endsWith("my-auth-key-01"));
        assertTrue(didDoc.get("verificationMethod").getAsJsonArray().get(1).getAsJsonObject().get("id").getAsString().endsWith("assert-key-01")); // default

        //System.out.println(didLogEntry);

        //assertTrue("""
        //        """.contains(didLogEntry));
    }

    @DisplayName("Throwing 'no such kid' ParseException")
    @ParameterizedTest(name = "For (here irrelevant) identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testThrowsNoSuchKidParseException(URL identifierRegistryUrl) throws IOException {

        assertThrowsExactly(ParseException.class, () -> {
            TdwCreator.builder()
                    .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .assertionMethodKeys(Map.of(
                            "nonexisting-key-id",
                            JwkUtils.loadPublicJWKasJSON(new File("src/test/data/myjsonwebkeys.json"), "nonexisting-key-id")
                    ))
                    .build()
                    .create(identifierRegistryUrl, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT
        });

        assertThrowsExactly(ParseException.class, () -> {
            TdwCreator.builder()
                    .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .authenticationKeys(Map.of(
                            "nonexisting-key-id",
                            JwkUtils.loadPublicJWKasJSON(new File("src/test/data/myjsonwebkeys.json"), "nonexisting-key-id")
                    ))
                    .build()
                    .create(identifierRegistryUrl, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT
        });

    }
}
