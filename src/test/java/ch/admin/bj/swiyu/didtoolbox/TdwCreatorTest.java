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
                            "my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01")
                    ))
                    .authenticationKeys(Map.of(
                            "my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01")
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
                ["1-QmT8t5pFKKapqdx9GB8DZYM489UrXWMYu6v2WjfzPSu8gM","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmPJ85fz4FMocjsm6qqHkN2DqJLYJLQwvXAcNDFemM1Jgg","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:QmPJ85fz4FMocjsm6qqHkN2DqJLYJLQwvXAcNDFemM1Jgg:127.0.0.1%3A54858","authentication":["did:tdw:QmPJ85fz4FMocjsm6qqHkN2DqJLYJLQwvXAcNDFemM1Jgg:127.0.0.1%3A54858#my-auth-key-01"],"assertionMethod":["did:tdw:QmPJ85fz4FMocjsm6qqHkN2DqJLYJLQwvXAcNDFemM1Jgg:127.0.0.1%3A54858#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmPJ85fz4FMocjsm6qqHkN2DqJLYJLQwvXAcNDFemM1Jgg:127.0.0.1%3A54858#my-auth-key-01","controller":"did:tdw:QmPJ85fz4FMocjsm6qqHkN2DqJLYJLQwvXAcNDFemM1Jgg:127.0.0.1%3A54858","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"5rEMXDhL_-SXbtEyJlbsbKUGUkJDBexRH4Yb3rlVZbg","y":"q0IJ1nf1lz5deOO2oOuyfBjrcWkTQEZw8XHHj4fJBZE"}},{"id":"did:tdw:QmPJ85fz4FMocjsm6qqHkN2DqJLYJLQwvXAcNDFemM1Jgg:127.0.0.1%3A54858#my-assert-key-01","controller":"did:tdw:QmPJ85fz4FMocjsm6qqHkN2DqJLYJLQwvXAcNDFemM1Jgg:127.0.0.1%3A54858","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"Lzv4BEZcBEqiz1VdXxjK77ZXYVeNU_Mk-8NthFVyZw8","y":"9KMUUR4fcB1LfLAJGQ76qYxvEtN82yosOlqUYgQvdq8"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmT8t5pFKKapqdx9GB8DZYM489UrXWMYu6v2WjfzPSu8gM","proofValue":"z4Aod3abW31K5ur1kjgk1wpb7xhbDK7WSHHYJAft2fr4KDJtCVEcKowEeKukKf7vpGjdBnY2neLZjtP9ghBPEEAfF"}]]
                ["1-QmVALuFKhFv91SP4sMajQgBi49aHR6wn8MKFA4KL289G1t","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmUSyQohHF4tcRhdkJYoamuMQAXQmYBoFLCot35xd7dPda","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:QmUSyQohHF4tcRhdkJYoamuMQAXQmYBoFLCot35xd7dPda:127.0.0.1%3A54858:123456789","authentication":["did:tdw:QmUSyQohHF4tcRhdkJYoamuMQAXQmYBoFLCot35xd7dPda:127.0.0.1%3A54858:123456789#my-auth-key-01"],"assertionMethod":["did:tdw:QmUSyQohHF4tcRhdkJYoamuMQAXQmYBoFLCot35xd7dPda:127.0.0.1%3A54858:123456789#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmUSyQohHF4tcRhdkJYoamuMQAXQmYBoFLCot35xd7dPda:127.0.0.1%3A54858:123456789#my-auth-key-01","controller":"did:tdw:QmUSyQohHF4tcRhdkJYoamuMQAXQmYBoFLCot35xd7dPda:127.0.0.1%3A54858:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"5rEMXDhL_-SXbtEyJlbsbKUGUkJDBexRH4Yb3rlVZbg","y":"q0IJ1nf1lz5deOO2oOuyfBjrcWkTQEZw8XHHj4fJBZE"}},{"id":"did:tdw:QmUSyQohHF4tcRhdkJYoamuMQAXQmYBoFLCot35xd7dPda:127.0.0.1%3A54858:123456789#my-assert-key-01","controller":"did:tdw:QmUSyQohHF4tcRhdkJYoamuMQAXQmYBoFLCot35xd7dPda:127.0.0.1%3A54858:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"Lzv4BEZcBEqiz1VdXxjK77ZXYVeNU_Mk-8NthFVyZw8","y":"9KMUUR4fcB1LfLAJGQ76qYxvEtN82yosOlqUYgQvdq8"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmVALuFKhFv91SP4sMajQgBi49aHR6wn8MKFA4KL289G1t","proofValue":"zLyKtHnM6tEJS9infDS8i5fHSK8aX16Y8xGzP2i91QTbmfwzJh9W35KqkUny2kmYMZWfFCgWHXZ82SWGss9Muups"}]]
                ["1-QmSPNKfNW4CrwLQnoWDppEeu9TYFY2f2z5xzWZ96neeU8C","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmcTh4ghpn5HHuubeGzt5JMS9PfAyxZLVPn3zTq3TYP69v","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:QmcTh4ghpn5HHuubeGzt5JMS9PfAyxZLVPn3zTq3TYP69v:127.0.0.1%3A54858:123456789:123456789","authentication":["did:tdw:QmcTh4ghpn5HHuubeGzt5JMS9PfAyxZLVPn3zTq3TYP69v:127.0.0.1%3A54858:123456789:123456789#my-auth-key-01"],"assertionMethod":["did:tdw:QmcTh4ghpn5HHuubeGzt5JMS9PfAyxZLVPn3zTq3TYP69v:127.0.0.1%3A54858:123456789:123456789#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmcTh4ghpn5HHuubeGzt5JMS9PfAyxZLVPn3zTq3TYP69v:127.0.0.1%3A54858:123456789:123456789#my-auth-key-01","controller":"did:tdw:QmcTh4ghpn5HHuubeGzt5JMS9PfAyxZLVPn3zTq3TYP69v:127.0.0.1%3A54858:123456789:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"5rEMXDhL_-SXbtEyJlbsbKUGUkJDBexRH4Yb3rlVZbg","y":"q0IJ1nf1lz5deOO2oOuyfBjrcWkTQEZw8XHHj4fJBZE"}},{"id":"did:tdw:QmcTh4ghpn5HHuubeGzt5JMS9PfAyxZLVPn3zTq3TYP69v:127.0.0.1%3A54858:123456789:123456789#my-assert-key-01","controller":"did:tdw:QmcTh4ghpn5HHuubeGzt5JMS9PfAyxZLVPn3zTq3TYP69v:127.0.0.1%3A54858:123456789:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"Lzv4BEZcBEqiz1VdXxjK77ZXYVeNU_Mk-8NthFVyZw8","y":"9KMUUR4fcB1LfLAJGQ76qYxvEtN82yosOlqUYgQvdq8"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmSPNKfNW4CrwLQnoWDppEeu9TYFY2f2z5xzWZ96neeU8C","proofValue":"z4nfDgKkUvzrAdYjVQMhTec8bqPT5AoCbmeXSm9yzcdhMHpTmy2t23Jb1USJxMpu2X4pjM6enzcaxudsWmKACCh9P"}]]
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
}
