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
                ["1-QmSSZ4VVDM7Edd6H4hvueu9yuEppibRSUN9USZ222M9jSv","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmeLapUpgZeyyCmjG8vRKjXYwEAXaYJyAT4ohzR73jZf1A","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:QmeLapUpgZeyyCmjG8vRKjXYwEAXaYJyAT4ohzR73jZf1A:127.0.0.1%3A54858","authentication":["did:tdw:QmeLapUpgZeyyCmjG8vRKjXYwEAXaYJyAT4ohzR73jZf1A:127.0.0.1%3A54858#my-auth-key-01"],"assertionMethod":["did:tdw:QmeLapUpgZeyyCmjG8vRKjXYwEAXaYJyAT4ohzR73jZf1A:127.0.0.1%3A54858#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmeLapUpgZeyyCmjG8vRKjXYwEAXaYJyAT4ohzR73jZf1A:127.0.0.1%3A54858#my-auth-key-01","controller":"did:tdw:QmeLapUpgZeyyCmjG8vRKjXYwEAXaYJyAT4ohzR73jZf1A:127.0.0.1%3A54858","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmeLapUpgZeyyCmjG8vRKjXYwEAXaYJyAT4ohzR73jZf1A:127.0.0.1%3A54858#my-assert-key-01","controller":"did:tdw:QmeLapUpgZeyyCmjG8vRKjXYwEAXaYJyAT4ohzR73jZf1A:127.0.0.1%3A54858","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmSSZ4VVDM7Edd6H4hvueu9yuEppibRSUN9USZ222M9jSv","proofValue":"z2N9GR3FjdVPEawad7Y9S5zCseJXNooECnsrHN4v9r5feZuWVSzZeQeHfHTnz1tXEuHkbLrK3CEacsCbx9Tyn2A6e"}]]
                ["1-QmX2ZK9UhsPRHuZg2VcVvEqr6NAouSsj7YDRyQUxjdDdcS","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmVb1zd51cpgYuNd8DMk39pDSjwJ894qBbfzmoa32T9g6x","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:QmVb1zd51cpgYuNd8DMk39pDSjwJ894qBbfzmoa32T9g6x:127.0.0.1%3A54858:123456789","authentication":["did:tdw:QmVb1zd51cpgYuNd8DMk39pDSjwJ894qBbfzmoa32T9g6x:127.0.0.1%3A54858:123456789#my-auth-key-01"],"assertionMethod":["did:tdw:QmVb1zd51cpgYuNd8DMk39pDSjwJ894qBbfzmoa32T9g6x:127.0.0.1%3A54858:123456789#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmVb1zd51cpgYuNd8DMk39pDSjwJ894qBbfzmoa32T9g6x:127.0.0.1%3A54858:123456789#my-auth-key-01","controller":"did:tdw:QmVb1zd51cpgYuNd8DMk39pDSjwJ894qBbfzmoa32T9g6x:127.0.0.1%3A54858:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmVb1zd51cpgYuNd8DMk39pDSjwJ894qBbfzmoa32T9g6x:127.0.0.1%3A54858:123456789#my-assert-key-01","controller":"did:tdw:QmVb1zd51cpgYuNd8DMk39pDSjwJ894qBbfzmoa32T9g6x:127.0.0.1%3A54858:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmX2ZK9UhsPRHuZg2VcVvEqr6NAouSsj7YDRyQUxjdDdcS","proofValue":"z2iJi55BwP575YPgDHBbA3i3aC1GNEwTaZrrXfrHeVh7uui5e9gL6ELfA7xJescagQg7R78a73xXg8BYyMxnk48EH"}]]
                ["1-QmYCunie8tegy8Rcoi7mHx2cCwXZmoxdLQE8V4WtcxBRHZ","2012-12-12T12:12:12Z",{"method":"did:tdw:0.3","scid":"QmYp8kzWT61YYeAfZSYtBCtBnpnoeF5fkKJLoUVFPypB7G","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:QmYp8kzWT61YYeAfZSYtBCtBnpnoeF5fkKJLoUVFPypB7G:127.0.0.1%3A54858:123456789:123456789","authentication":["did:tdw:QmYp8kzWT61YYeAfZSYtBCtBnpnoeF5fkKJLoUVFPypB7G:127.0.0.1%3A54858:123456789:123456789#my-auth-key-01"],"assertionMethod":["did:tdw:QmYp8kzWT61YYeAfZSYtBCtBnpnoeF5fkKJLoUVFPypB7G:127.0.0.1%3A54858:123456789:123456789#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmYp8kzWT61YYeAfZSYtBCtBnpnoeF5fkKJLoUVFPypB7G:127.0.0.1%3A54858:123456789:123456789#my-auth-key-01","controller":"did:tdw:QmYp8kzWT61YYeAfZSYtBCtBnpnoeF5fkKJLoUVFPypB7G:127.0.0.1%3A54858:123456789:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmYp8kzWT61YYeAfZSYtBCtBnpnoeF5fkKJLoUVFPypB7G:127.0.0.1%3A54858:123456789:123456789#my-assert-key-01","controller":"did:tdw:QmYp8kzWT61YYeAfZSYtBCtBnpnoeF5fkKJLoUVFPypB7G:127.0.0.1%3A54858:123456789:123456789","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2012-12-12T12:12:12Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmYCunie8tegy8Rcoi7mHx2cCwXZmoxdLQE8V4WtcxBRHZ","proofValue":"z3yQRoRPgwdYx1pjcnfqMyyKq31SbUWcaGbW1hnpwipevMNvmFQFN1cxHX3eb2k7kqv5cs6cRoNyoNhSjFfsAhP74"}]]
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
