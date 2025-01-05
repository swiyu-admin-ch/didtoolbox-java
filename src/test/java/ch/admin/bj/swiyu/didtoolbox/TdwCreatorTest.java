package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

//@Disabled
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

    private static Collection<Object[]> domainPath() {
        return Arrays.asList(new String[][]{
                {"https://127.0.0.1:54858", null},
                {"https://127.0.0.1:54858", "123456789"},
                {"https://127.0.0.1:54858", "123456789/123456789"},
        });
    }

    @DisplayName("Building TDW log entry for various domain(:path) variants")
    @ParameterizedTest(name = "For domain {0} and path {1}")
    @MethodSource("domainPath")
    public void testBuild(String domain, String path) {

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .signer(new Ed25519SignerVerifier())
                    .build()
                    .create(domain, path, ZonedDateTime.now()); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertDidLogEntry(didLogEntry);
    }

    @DisplayName("Building TDW log entry for various domain(:path) variants using Java Keystore (JKS)")
    @ParameterizedTest(name = "For domain {0} and path {1}")
    @MethodSource("domainPath")
    public void testBuildUsingJKS(String domain, String path) {

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .signer(new Ed25519SignerVerifier(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .build()
                    .create(domain, path, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

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

    @DisplayName("Building TDW log entry for various domain(:path) variants (incl. external authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For domain {0} and path {1}")
    @MethodSource("domainPath")
    public void testBuildUsingJksWithExternalVerificationMethodKeys(String domain, String path) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .signer(new Ed25519SignerVerifier(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .assertionMethodKeys(Map.of(
                            "my-assert-key-01", JwkUtils.load(new File("src/test/data/myjsonwebkeys.json"), "my-assert-key-01")
                    ))
                    .authenticationKeys(Map.of(
                            "my-auth-key-01", JwkUtils.load(new File("src/test/data/myjsonwebkeys.json"), "my-auth-key-01")
                    ))
                    .build()
                    .create(domain, path, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

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
                ["1-QmXLoDVxS4ykjhFW7J7iuKP6w3NXHQzVEH4dtdbbmtrdRv","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmVBRfpLNSjTsVtuoYxm9QTNZteAk6wbnpWa8LWbqrLpKi","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"nextKeyHashes":[],"witnesses":[],"witnessThreshold":0,"deactivated":false,"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmVBRfpLNSjTsVtuoYxm9QTNZteAk6wbnpWa8LWbqrLpKi:127.0.0.1%3A54858","controller":"did:tdw:QmVBRfpLNSjTsVtuoYxm9QTNZteAk6wbnpWa8LWbqrLpKi:127.0.0.1%3A54858","authentication":["did:tdw:QmVBRfpLNSjTsVtuoYxm9QTNZteAk6wbnpWa8LWbqrLpKi:127.0.0.1%3A54858#my-auth-key-01"],"assertionMethod":["did:tdw:QmVBRfpLNSjTsVtuoYxm9QTNZteAk6wbnpWa8LWbqrLpKi:127.0.0.1%3A54858#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmVBRfpLNSjTsVtuoYxm9QTNZteAk6wbnpWa8LWbqrLpKi:127.0.0.1%3A54858#my-auth-key-01","controller":"did:tdw:QmVBRfpLNSjTsVtuoYxm9QTNZteAk6wbnpWa8LWbqrLpKi:127.0.0.1%3A54858","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","kid":"my-auth-key-01","x":"6sp4uBi3AHRDEFM1wQIyEzjC_sGYDdnSo01N-s_zDYU"}},{"id":"did:tdw:QmVBRfpLNSjTsVtuoYxm9QTNZteAk6wbnpWa8LWbqrLpKi:127.0.0.1%3A54858#my-assert-key-01","controller":"did:tdw:QmVBRfpLNSjTsVtuoYxm9QTNZteAk6wbnpWa8LWbqrLpKi:127.0.0.1%3A54858","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","kid":"my-assert-key-01","x":"jcAGpa7VpH8SjTjxqXs1bqq8jUjKYE8IrYrU_XY4zg0"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmXLoDVxS4ykjhFW7J7iuKP6w3NXHQzVEH4dtdbbmtrdRv","proofValue":"z2uF4bYzixSkA6M5397Q791o9KzdQbrbyNBnsejEmS9Nk6HDpgNt3dU9GYVWTYCYiQGekGgRjXs4eAE4RfZZobEv8"}]]
                ["1-QmP19Mcje23JPEj4PuzGxCKuU64WJMtFVBMEJtPEhzsnhe","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmScfP3crUYLHz84EuCpGaDT6s7xoB9B9nHuECtq6fLioo","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"nextKeyHashes":[],"witnesses":[],"witnessThreshold":0,"deactivated":false,"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmScfP3crUYLHz84EuCpGaDT6s7xoB9B9nHuECtq6fLioo:127.0.0.1%3A54858:123456789","controller":"did:tdw:QmScfP3crUYLHz84EuCpGaDT6s7xoB9B9nHuECtq6fLioo:127.0.0.1%3A54858:123456789","authentication":["did:tdw:QmScfP3crUYLHz84EuCpGaDT6s7xoB9B9nHuECtq6fLioo:127.0.0.1%3A54858:123456789#my-auth-key-01"],"assertionMethod":["did:tdw:QmScfP3crUYLHz84EuCpGaDT6s7xoB9B9nHuECtq6fLioo:127.0.0.1%3A54858:123456789#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmScfP3crUYLHz84EuCpGaDT6s7xoB9B9nHuECtq6fLioo:127.0.0.1%3A54858:123456789#my-auth-key-01","controller":"did:tdw:QmScfP3crUYLHz84EuCpGaDT6s7xoB9B9nHuECtq6fLioo:127.0.0.1%3A54858:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","kid":"my-auth-key-01","x":"6sp4uBi3AHRDEFM1wQIyEzjC_sGYDdnSo01N-s_zDYU"}},{"id":"did:tdw:QmScfP3crUYLHz84EuCpGaDT6s7xoB9B9nHuECtq6fLioo:127.0.0.1%3A54858:123456789#my-assert-key-01","controller":"did:tdw:QmScfP3crUYLHz84EuCpGaDT6s7xoB9B9nHuECtq6fLioo:127.0.0.1%3A54858:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","kid":"my-assert-key-01","x":"jcAGpa7VpH8SjTjxqXs1bqq8jUjKYE8IrYrU_XY4zg0"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmP19Mcje23JPEj4PuzGxCKuU64WJMtFVBMEJtPEhzsnhe","proofValue":"z2ZE2vTsBUsVLGekxni98xg3GjM1BHiqf7yP3pzswE9ZWoEvyGX1CYeKQBZE9s6ocaaPDPAHABMfiZr6XLRbsaD6k"}]]
                ["1-QmX6SM1SLzJZmZQqCGJ6qg1g2mg1sRQDrk45qREZU6vbEY","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmZAgoC1ks7JjWfAgdpCKWHSrX6GCrqYDE99JxdYLCL9Ma","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"nextKeyHashes":[],"witnesses":[],"witnessThreshold":0,"deactivated":false,"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmZAgoC1ks7JjWfAgdpCKWHSrX6GCrqYDE99JxdYLCL9Ma:127.0.0.1%3A54858:123456789:123456789","controller":"did:tdw:QmZAgoC1ks7JjWfAgdpCKWHSrX6GCrqYDE99JxdYLCL9Ma:127.0.0.1%3A54858:123456789:123456789","authentication":["did:tdw:QmZAgoC1ks7JjWfAgdpCKWHSrX6GCrqYDE99JxdYLCL9Ma:127.0.0.1%3A54858:123456789:123456789#my-auth-key-01"],"assertionMethod":["did:tdw:QmZAgoC1ks7JjWfAgdpCKWHSrX6GCrqYDE99JxdYLCL9Ma:127.0.0.1%3A54858:123456789:123456789#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmZAgoC1ks7JjWfAgdpCKWHSrX6GCrqYDE99JxdYLCL9Ma:127.0.0.1%3A54858:123456789:123456789#my-auth-key-01","controller":"did:tdw:QmZAgoC1ks7JjWfAgdpCKWHSrX6GCrqYDE99JxdYLCL9Ma:127.0.0.1%3A54858:123456789:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","kid":"my-auth-key-01","x":"6sp4uBi3AHRDEFM1wQIyEzjC_sGYDdnSo01N-s_zDYU"}},{"id":"did:tdw:QmZAgoC1ks7JjWfAgdpCKWHSrX6GCrqYDE99JxdYLCL9Ma:127.0.0.1%3A54858:123456789:123456789#my-assert-key-01","controller":"did:tdw:QmZAgoC1ks7JjWfAgdpCKWHSrX6GCrqYDE99JxdYLCL9Ma:127.0.0.1%3A54858:123456789:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","kid":"my-assert-key-01","x":"jcAGpa7VpH8SjTjxqXs1bqq8jUjKYE8IrYrU_XY4zg0"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmX6SM1SLzJZmZQqCGJ6qg1g2mg1sRQDrk45qREZU6vbEY","proofValue":"z5Bu4ZUYSEcMLa9EskERLaGtCgdxh3A8cdP8zkLHDt7EJLeG5zVgLyDBiJ1X3vrcv6c5aLzqLBzQZ9typQd3C7vQ2"}]]
                """.contains(didLogEntry));
    }

    @DisplayName("Building TDW log entry for various domain(:path) variants (incl. generated authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For domain {0} and path {1}")
    @MethodSource("domainPath")
    public void testBuildUsingJksWithGeneratedVerificationMethodKeys(String domain, String path) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .signer(new Ed25519SignerVerifier(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .assertionMethodKeys(Map.of("my-assert-key-01", ""))
                    .authenticationKeys(Map.of("my-auth-key-01", ""))
                    .build()
                    .create(domain, path, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

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

    @DisplayName("Building TDW log entry for various domain(:path) variants (incl. generated authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For domain {0} and path {1}")
    @MethodSource("domainPath")
    public void testBuildUsingJksWithPartiallyGeneratedVerificationMethodKeys(String domain, String path) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .signer(new Ed25519SignerVerifier(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .assertionMethodKeys(Map.of("my-assert-key-01", ""))
                    //.authenticationKeys(Map.of("my-auth-key-01", ""))
                    .build()
                    .create(domain, path, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

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


    @DisplayName("Building TDW log entry for various domain(:path) variants (incl. generated authentication/assertion keys) using existing keys")
    @ParameterizedTest(name = "For domain {0} and path {1}")
    @MethodSource("domainPath")
    public void testBuildUsingJksWithPartiallyGeneratedVerificationMethodKeys2(String domain, String path) { // https://www.w3.org/TR/did-core/#assertion

        String didLogEntry = null;
        try {

            didLogEntry = TdwCreator.builder()
                    .signer(new Ed25519SignerVerifier(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    //.assertionMethodKeys(Map.of("my-assert-key-01", ""))
                    .authenticationKeys(Map.of("my-auth-key-01", ""))
                    .build()
                    .create(domain, path, ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT

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

    @Test
    public void testThrowsNoSuchKidException() throws IOException {

        assertThrowsExactly(ParseException.class, () -> {
            TdwCreator.builder()
                    .signer(new Ed25519SignerVerifier(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .assertionMethodKeys(Map.of(
                            "nonexisting-key-id",
                            JwkUtils.load(new File("src/test/data/myjsonwebkeys.json"), "nonexisting-key-id")
                    ))
                    .build()
                    .create("domain", "path", ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT
        });

        assertThrowsExactly(ParseException.class, () -> {
            TdwCreator.builder()
                    .signer(new Ed25519SignerVerifier(new FileInputStream("src/test/data/mykeystore.jks"), "changeit", "myalias"))
                    .authenticationKeys(Map.of(
                            "nonexisting-key-id",
                            JwkUtils.load(new File("src/test/data/myjsonwebkeys.json"), "nonexisting-key-id")
                    ))
                    .build()
                    .create("domain", "path", ZonedDateTime.parse("2012-12-12T12:12:12Z")); // MUT
        });

    }
}
