package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.NextKeyHashSource;
import ch.admin.bj.swiyu.didtoolbox.model.NamedDidMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.JcsSha256Hasher;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

// This will suppress all PMD warnings in this class
@SuppressWarnings({"PMD"})
class JCSHasherTest {

    final private static JcsSha256Hasher hasher = JcsSha256Hasher.Companion.build();

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
        parameters.add(NamedDidMethodParameters.UPDATE_KEYS, updateKeys);
        JsonArray nextKeyHashes = new JsonArray();
        nextKeyHashes.add("QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv");
        parameters.add(NamedDidMethodParameters.NEXT_KEY_HASHES, nextKeyHashes);

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

    private static JsonArray buildDidLog() throws DidSidekicksException { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        var didLogEntryWithoutProofAndSignature = buildDidLogEntryWithoutProofAndSignature();

        String scid = JcsSha256Hasher.Companion.build().base58btcEncodeMultihash(didLogEntryWithoutProofAndSignature.toString());

        String didLogEntryWithoutProofAndSignatureWithSCID = didLogEntryWithoutProofAndSignature.toString().replace("{SCID}", scid);

        return JsonParser.parseString(didLogEntryWithoutProofAndSignatureWithSCID).getAsJsonArray();
    }

    @DisplayName("Calculating multihash value")
    @ParameterizedTest(name = "For input {0}")
    @MethodSource("multihashInputExpected")
    public void testMultihash(String input, String expectedHex) {

        assertDoesNotThrow(() -> {
            assertEquals(expectedHex, HexFormat.of().formatHex(JCSHasher.multihash(input))); // MUT
        });
    }

    @Test
    public void testBuildSCID() { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        assertDoesNotThrow(() -> {
            assertEquals("Qma6mc1qZw3NqxwX6SB5GPQYzP4pGN2nXD15Jwi4bcDBKu", hasher.base58btcEncodeMultihash(buildDidLogEntryWithoutProofAndSignature().toString())); // MUT
        });
    }

    @Test
    public void testBuildNextKeyHash() {

        // See https://identity.foundation/didwebvh/v0.3/#log-file-for-version-2
        assertEquals("QmcbM5bppyT4yyaL35TQQJ2XdSrSNAhH5t6f4ZcuyR4VSv", NextKeyHashSource.of("z82Lkvgj5NKYhoFh4hWzax9WicQaVDphN8MMzR3JZhontVfHaoGd9JbC4QRpDvmjQH3BLeQ").getHash());

        // See https://github.com/affinidi/affinidi-tdk-rs/blob/main/crates/affinidi-tdk/common/affinidi-secrets-resolver/src/secrets.rs#L456
        assertEquals("QmY1kaguPMgjndEh1sdDZ8kdjX4Uc1SW4vziMfgWC6ndnJ", NextKeyHashSource.of("z6MkgfFvvWA7sw8WkNWyK3y74kwNVvWc7Qrs5tWnsnqMfLD3").getHash());

        // See https://raw.githubusercontent.com/decentralized-identity/didwebvh-rs/refs/heads/main/tests/test_vectors/pre-1_0-spec.jsonl
        assertEquals("QmPyrGjbkwKPbDE33StNmA6v9uwNWB9NWgmxMiQ7tV1uJx", NextKeyHashSource.of("z6Mkk7qfjoovyci2wpD1GZPvkngtWBjLr4bVdYeZfdWHDkEu").getHash());
        assertEquals("QmWZg7NR5vyjxHFjNLzyUdpHKXFr6MWM7pQJE8wdKrDZwV", NextKeyHashSource.of("z6MkmpTLDBwKi8qWC6J8jz4sGR9zn1oLTizNt6XbYxDEkFQS").getHash());

        // See https://raw.githubusercontent.com/decentralized-identity/didwebvh-rs/refs/heads/main/tests/test_vectors/revoked-did.jsonl
        assertEquals("QmeLTcLUJ9A2TTHeWdo2xx6yd52E4aPrLoEDnmCbUEhYUi", NextKeyHashSource.of("z6Mkr7XVfuk77YmHG9WWX3rxhLRzK2z7oEia7D75fpZC6dzG").getHash());
        assertEquals("QmejLZab9j1DuA8fD5593XXGS2WXUgKsh3jYGY8ctaSdyC", NextKeyHashSource.of("z6MkiwKu88uSsuNP5tYVvcaQSc7ZVpe1248zefnQXtbeHcxE").getHash());
    }

    @Test
    public void testBuildEntryHash() { // according to https://identity.foundation/didwebvh/v0.3/#didtdw-example

        String actual = null;
        try {

            actual = hasher.base58btcEncodeMultihash(buildDidLog().toString()); // MUT

        } catch (Exception e) {
            fail(e);
        }

        assertEquals("QmdwvukAYUU6VYwqM4jQbSiKk1ctg12j5hMTY6EfbbkyEJ", actual);
    }

    @Test
    public void testBuildDataIntegrityProofExample() { // according to https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022

        assertDoesNotThrow(() -> {
            var credentialsWithoutProof = JsonParser.parseString(CREDENTIAL_WITHOUT_PROOF).getAsJsonObject();

            JsonObject actual = JCSHasher.buildDataIntegrityProof(
                    credentialsWithoutProof,
                    true,
                    // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-1
                    new EdDsaJcs2022VcDataIntegrityCryptographicSuite("z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"),
                    null, // CAUTION The original PROOF_OPTIONS_DOCUMENT features NO proof's challenge!
                    "assertionMethod",
                    ZonedDateTime.parse("2023-02-24T23:36:38Z"));

            String actualProofValue = actual.asMap().get("proofValue").getAsString();
            // As suggested by https://www.w3.org/TR/vc-di-eddsa/#example-signature-of-combined-hashes-base58-btc-1
            assertEquals("z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX", actualProofValue);
        });
    }
}