package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class JCSHasherTest {

    private static Collection<Object[]> multihashInputExpected() {
        return Arrays.asList(new String[][]{
                // https://multiformats.io/multihash/#sha2-256---256-bits-aka-sha256
                {"Merkle–Damgård", "122041dd7b6443542e75701aa98a0c235951a28a0d851b11564d20022ab11d2589a8"},
        });
    }

    @DisplayName("Calculating multihash value")
    @ParameterizedTest(name = "For input {0}")
    @MethodSource("multihashInputExpected")
    public void testMultihash(String input, String expectedHex) {

        String actual = null;
        try {

            actual = HexFormat.of().formatHex(JCSHasher.multihash(input)); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertEquals(expectedHex, actual);
    }

    private static JsonArray buildDidLogEntryWithoutProofAndSignature() { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        JsonArray didLogEntryWithoutProofAndSignature = new JsonArray();
        didLogEntryWithoutProofAndSignature.add("{SCID}");
        didLogEntryWithoutProofAndSignature.add("2024-07-29T17:00:27Z");

        var parameters = new JsonObject();
        parameters.addProperty("prerotation", true);

        JsonArray updateKeys = new JsonArray();
        updateKeys.add("z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc");
        parameters.add("updateKeys", updateKeys);
        JsonArray nextKeyHashes = new JsonArray();
        nextKeyHashes.add("QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv");
        parameters.add("nextKeyHashes", nextKeyHashes);

        parameters.addProperty("method", "did:tdw:0.3");
        parameters.addProperty("scid", "{SCID}");
        didLogEntryWithoutProofAndSignature.add(parameters);

        var context = new JsonArray();
        context.add("https://www.w3.org/ns/did/v1");
        context.add("https://w3id.org/security/multikey/v1");

        // Create initial did doc with placeholder
        var genesisDidDoc = new JsonObject();
        genesisDidDoc.add("@context", context);
        genesisDidDoc.addProperty("id", "did:tdw:{SCID}:domain.example");

        JsonObject initialDidDoc = new JsonObject();
        initialDidDoc.add("value", genesisDidDoc);
        didLogEntryWithoutProofAndSignature.add(initialDidDoc);

        return didLogEntryWithoutProofAndSignature;
    }

    private static JsonArray buildDidLog() throws NoSuchAlgorithmException, IOException { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        var didLogEntryWithoutProofAndSignature = buildDidLogEntryWithoutProofAndSignature();

        String scid = JCSHasher.buildSCID(didLogEntryWithoutProofAndSignature);

        // CAUTION "\\" prevents "java.util.regex.PatternSyntaxException: Illegal repetition near index 1"
        String didDocWithSCID = didLogEntryWithoutProofAndSignature.toString().replaceAll("\\{SCID}", scid);

        return JsonParser.parseString(didDocWithSCID).getAsJsonArray();
    }


    private static JsonObject buildProofJsonObject() throws NoSuchAlgorithmException, IOException {

        //JsonArray jsonArray = new JsonArray();

        JsonObject proof = new JsonObject();
        proof.addProperty("type", "DataIntegrityProof");
        proof.addProperty("cryptoSuite", "eddsa-jcs-2022");
        //proof.addProperty("created", ZonedDateTime.now().format(DateTimeFormatter.ISO_INSTANT.withZone(ZoneId.systemDefault())));
        proof.addProperty("created", "2024-07-29T17:00:27Z");

        /*
        The data integrity proof verificationMethod is the did:key from the first log entry, and the challenge is the versionId from this log entry.
         */
        proof.addProperty("verificationMethod", "did:key:z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc#z82LkvR3CBNkb9tUVps4GhGpNvEVP6vWzdwgGwQbA1iYoZwd7m1F1hSvkJFSe6sWci7JiXc");
        proof.addProperty("proofPurpose", "authentication");
        proof.addProperty("challenge", "1-QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ"); // the same as: proof.addProperty("challenge", "1-" + JCSHasher.buildSCID(buildGenesisDidDoc()));

        //jsonArray.add(proof);

        return proof;
    }


    @Test
    public void testBuildSCID() { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        String actual = null;
        try {

            actual = JCSHasher.buildSCID(buildDidLogEntryWithoutProofAndSignature()); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertEquals("Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu", actual);
    }


    @Test
    public void testBuildEntryHash() { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        String actual = null;
        try {

            actual = JCSHasher.buildSCID(buildDidLog()); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertEquals("QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ", actual);
    }

    @Test
    public void testBuildProofJsonObjects() { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        var context = new JsonArray();
        context.add("https://www.w3.org/ns/did/v1");
        context.add("https://w3id.org/security/multikey/v1");

        var genesisDidDoc = new JsonObject();
        genesisDidDoc.add("@context", context);
        genesisDidDoc.addProperty("id", "did:tdw:Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu:domain.example");

        String actual = null;
        try {

            String genesisDidDocHashHex = JCSHasher.hashJsonObjectAsHex(genesisDidDoc);
            assertEquals("d3c39687647f64d2a94f39f65c188881ca79a6f24379543bd44e9539aa8bcd4c", genesisDidDocHashHex);

            var proofJsonObject = buildProofJsonObject();
            String proofHashHex = JCSHasher.hashJsonObjectAsHex(buildProofJsonObject());
            assertEquals("ab6dbc1f63f15aeec98fb01a36696dd3cf42b74c1b0a0d1a3bb37a9d66557cdc", proofHashHex);

            actual = JCSHasher.buildProof(
                    proofJsonObject,
                    genesisDidDoc,
                    new Signer("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq", "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"));

        } catch (Exception e) {
            fail(e);
        }

        assertEquals("z4hTWacFW34893QNPXh4zzGskaixEMWteqaHrmRKg7YgQhQ5Kt2v2RChdB1tzqXVv5BhkzfxdyY3xfGghezeY2aVQ", actual);
    }

    @Test
    public void testBuildProof() { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        String actual = null;
        try {

            var doc = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\",\"https://www.w3.org/ns/credentials/examples/v2\"],\"credentialSubject\":{\"alumniOf\":\"The School of Examples\",\"id\":\"did:example:abcdefgh\"},\"description\":\"A minimum viable example of an Alumni Credential.\",\"id\":\"urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33\",\"issuer\":\"https://vc.example/issuers/5678\",\"name\":\"Alumni Credential\",\"type\":[\"VerifiableCredential\",\"AlumniCredential\"],\"validFrom\":\"2023-01-01T00:00:00Z\"}";
            String docHashHex = JCSHasher.hashJsonObjectAsHex(JsonParser.parseString(doc).getAsJsonObject());
            assertEquals("59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19", docHashHex);

            var proof = "{\"created\":\"2023-02-24T23:36:38Z\",\"cryptosuite\":\"eddsa-jcs-2022\",\"proofPurpose\":\"assertionMethod\",\"type\":\"DataIntegrityProof\",\"verificationMethod\":\"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2\"}";
            String proofHashHex = JCSHasher.hashJsonObjectAsHex(JsonParser.parseString(proof).getAsJsonObject());
            assertEquals("c46b3487ab7087c4f426b546c449094ff57b8fefa6fd85e83f1b31e24c230da8", proofHashHex);

            actual = JCSHasher.buildProof(
                    JsonParser.parseString(proof).getAsJsonObject(),
                    JsonParser.parseString(doc).getAsJsonObject(),
                    new Signer("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq", "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"));

        } catch (Exception e) {
            fail(e);
        }

        assertEquals("zboydVv31kj6jP37GMBZwYyjbvrqr9MWeY9NCEfYUwLcKwkdqAcB44dqEcqaMi8mfdvT2Vbnvdrv6XRaYzgpuPWn", actual);
    }
}