package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all PMD warnings in this class
@SuppressWarnings({"PMD"})
class JCSHasherTest {

    // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-credential-without-proof-0
    private static final String CREDENTIAL_WITHOUT_PROOF = """
            {
                 "@context": [
                     "https://www.w3.org/ns/credentials/v2",
                     "https://www.w3.org/ns/credentials/examples/v2"
                 ],
                 "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
                 "type": ["VerifiableCredential", "AlumniCredential"],
                 "name": "Alumni Credential",
                 "description": "A minimum viable example of an Alumni Credential.",
                 "issuer": "https://vc.example/issuers/5678",
                 "validFrom": "2023-01-01T00:00:00Z",
                 "credentialSubject": {
                     "id": "did:example:abcdefgh",
                     "alumniOf": "The School of Examples"
                 }
            }
            """;

    // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-proof-options-document-1
    private static final String PROOF_OPTIONS_DOCUMENT = """
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "created": "2023-02-24T23:36:38Z",
                "verificationMethod": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
                "proofPurpose": "assertionMethod",
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://www.w3.org/ns/credentials/examples/v2"
               ]
            }
            """;

    private static Collection<Object[]> multihashInputExpected() {
        return Arrays.asList(new String[][]{
                // As suggested by https://multiformats.io/multihash/#sha2-256---256-bits-aka-sha256
                {"Merkle–Damgård", "122041dd7b6443542e75701aa98a0c235951a28a0d851b11564d20022ab11d2589a8"},
        });
    }

    // From https://identity.foundation/didwebvh/v0.3/#didtdw-example
    private static JsonArray buildDidLogEntryWithoutProofAndSignature() {

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

    private static JsonArray buildDidLog() throws IOException { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        var didLogEntryWithoutProofAndSignature = buildDidLogEntryWithoutProofAndSignature();

        String scid = JCSHasher.buildSCID(didLogEntryWithoutProofAndSignature.toString());

        // CAUTION "\\" prevents "java.util.regex.PatternSyntaxException: Illegal repetition near index 1"
        String didLogEntryWithoutProofAndSignatureWithSCID = didLogEntryWithoutProofAndSignature.toString().replaceAll("\\{SCID}", scid);

        return JsonParser.parseString(didLogEntryWithoutProofAndSignatureWithSCID).getAsJsonArray();
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

    @Test
    public void testBuildSCID() { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        String actual = null;
        try {

            actual = JCSHasher.buildSCID(buildDidLogEntryWithoutProofAndSignature().toString()); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertEquals("Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu", actual);
    }


    @Test
    public void testBuildEntryHash() { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        String actual = null;
        try {

            actual = JCSHasher.buildSCID(buildDidLog().toString()); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertEquals("QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ", actual);
    }


    @Test
    public void testHashJsonObjectAsHex() { // according to https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022

        String actualDocHashHex = null;
        String actualProofHashHex = null;

        try {

            actualDocHashHex = JCSHasher.hashJsonObjectAsHex(JsonParser.parseString(CREDENTIAL_WITHOUT_PROOF).getAsJsonObject());
            actualProofHashHex = JCSHasher.hashJsonObjectAsHex(JsonParser.parseString(PROOF_OPTIONS_DOCUMENT).getAsJsonObject());

        } catch (Exception e) {
            fail(e);
        }

        // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-credential-without-proof-hex-0
        assertEquals("59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19", actualDocHashHex);
        // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-proof-options-document-hex-1
        assertEquals("66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db", actualProofHashHex);
    }

    @Test
    public void testBuildDataIntegrityProof() { // according to https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022

        var credentialsWithoutProof = JsonParser.parseString(CREDENTIAL_WITHOUT_PROOF).getAsJsonObject();
        try {

            String docHashHex = JCSHasher.hashJsonObjectAsHex(credentialsWithoutProof);
            // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-credential-without-proof-hex-0
            assertEquals("59b7cb6251b8991add1ce0bc83107e3db9dbbab5bd2c28f687db1a03abc92f19", docHashHex);

            String expectedProofHashHex = JCSHasher.hashJsonObjectAsHex(JsonParser.parseString(PROOF_OPTIONS_DOCUMENT).getAsJsonObject());
            // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-proof-options-document-hex-1
            assertEquals("66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db", expectedProofHashHex);

            JsonObject actual = JCSHasher.buildDataIntegrityProof(
                    credentialsWithoutProof,
                    true,
                    // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
                    new UnsafeEd25519VerificationMethodKeyProviderImpl("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq", "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"),
                    "1-" + JCSHasher.buildSCID(credentialsWithoutProof.toString()), // CAUTION The original PROOF_OPTIONS_DOCUMENT features NO proof's challenge!
                    "assertionMethod",
                    ZonedDateTime.parse("2023-02-24T23:36:38Z"));

            String actualProofValue = actual.asMap().get("proofValue").getAsString();
            // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-base58-btc-1
            // CAUTION The value suggested in the spec (z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX)
            //         is irrelevant here since the PROOF_OPTIONS_DOCUMENT (suggested by https://www.w3.org/TR/vc-di-eddsa/#example-proof-options-document-1)
            //         features NO proof's challenge.
            assertEquals("z3swhrb2DFocc562PATcKiv8YtjUzxLdfr4dhb9DidvG2BNkJqAXe65bsEMiNJdGKDdnYxiBa7cKXXw4cSKCvMcfm", actualProofValue);

            assertNotNull(actual.remove("proofValue"));
            // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-hash-of-canonical-proof-options-document-hex-1
            // CAUTION The value suggested in the spec (66ab154f5c2890a140cb8388a22a160454f80575f6eae09e5a097cabe539a1db)
            //         is irrelevant here since the PROOF_OPTIONS_DOCUMENT (suggested by https://www.w3.org/TR/vc-di-eddsa/#example-proof-options-document-1)
            //         features NO proof's challenge.
            assertEquals("49dc22583675513d1f0018c7e855bb8406a33d800cadced81838704a0d5d9615", JCSHasher.hashJsonObjectAsHex(actual));

        } catch (Exception e) {
            fail(e);
        }
    }
}