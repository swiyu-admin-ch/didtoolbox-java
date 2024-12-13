package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import io.ipfs.multibase.Base58;
import lombok.Builder;
import lombok.Getter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Map;

@Builder
@Getter
public class TdwCreator {

    private Map<String, AssertionMethodInput> assertionMethods;
    private Signer signer;

    /**
     * @param domain
     * @param path   (optional)
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public String create(String domain, String path) throws NoSuchAlgorithmException, IOException {
        return create(domain, path, ZonedDateTime.now());
    }

    /**
     * Package-scope and therefore more potent method.
     *
     * @param domain
     * @param path   (optional)
     * @param now
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    String create(String domain, String path, ZonedDateTime now) throws NoSuchAlgorithmException, IOException {

        // Method-Specific Identifier: https://identity.foundation/didwebvh/v0.3/#method-specific-identifier
        String didTDW = "did:tdw:{SCID}:" + domain.replace("https://", "").replace(":", "%3A");
        if (path != null && !path.isEmpty()) {
            didTDW += ":" + path.replaceAll("/", ":");
        }

        var keyDef = new JsonObject();
        keyDef.add("type", new JsonPrimitive("Ed25519VerificationKey2020"));
        keyDef.addProperty("publicKeyMultibase", this.signer.getEd25519VerificationKey2020());

        String keyDefHashMultibase = 'z' + Base58.encode(JCSHasher.hashJsonObject(keyDef).getBytes(StandardCharsets.UTF_8));

        // Create verification method for subject with placeholder
        JsonArray verificationMethod = new JsonArray();
        JsonObject verificationMethodObj = new JsonObject();
        //verificationMethod.addProperty("id", didTDW + "#" + verificationMethodSuffix);
        verificationMethodObj.addProperty("id", didTDW + "#" + keyDefHashMultibase);
        verificationMethodObj.addProperty("controller", didTDW);
        verificationMethodObj.addProperty("type", "Ed25519VerificationKey2020");
        verificationMethodObj.addProperty("publicKeyMultibase", this.signer.getEd25519VerificationKey2020());
        //verificationMethod.addProperty("publicKeyJwk", (String)null);
        verificationMethod.add(verificationMethodObj);

        var context = new JsonArray();
        context.add("https://www.w3.org/ns/did/v1");
        context.add("https://w3id.org/security/multikey/v1");

        // Create initial did doc with placeholder
        var didDoc = new JsonObject();
        didDoc.add("@context", context);
        didDoc.addProperty("id", didTDW);
        didDoc.add("verificationMethod", verificationMethod);
        didDoc.add("authentication", verificationMethod);

        if (this.assertionMethods != null) {

            JsonArray assertionMethod = new JsonArray();
            String finalDidTDW = didTDW;
            this.assertionMethods.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach((e) -> {
                JsonObject assertionMethodObj = new JsonObject();
                assertionMethodObj.addProperty("id", finalDidTDW + "#" + e.getKey());
                assertionMethodObj.addProperty("type", "Ed25519VerificationKey2020");
                assertionMethodObj.addProperty("controller", finalDidTDW);

                String publicKeyMultibase = this.signer.getEd25519VerificationKey2020(); // fallback
                if (e.getValue().getAssertionPublicKey() != null) {
                    publicKeyMultibase = e.getValue().getAssertionPublicKey();
                }
                assertionMethodObj.addProperty("publicKeyMultibase", publicKeyMultibase);

                assertionMethod.add(assertionMethodObj);
            });

            didDoc.add("assertionMethod", assertionMethod);
        }

        var controller = new JsonArray();
        controller.add(didTDW);
        didDoc.add("controller", controller);
        //verificationMethod.addProperty("deactivated", (Boolean)null);

        // Generate SCID and replace placeholder in did doc
        var scid = 'Q' + Base58.encode(JCSHasher.hashJsonObject(didDoc).getBytes(StandardCharsets.UTF_8));

        /* https://identity.foundation/trustdidweb/v0.3/#output-of-the-scid-generation-process:
        After the SCID is generated, the literal {SCID} placeholders are replaced by the generated SCID value (below).
        This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        Once the process has run, the version number of this first version of the DID (1),
        a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
         */

        String didDocWithSCID = didDoc.toString().replaceAll("\\{SCID}", scid);

        /*
        Generate a preliminary DID Log Entry (input JSON array)
        The DID log entry is an input JSON array that when completed contains the following items:
        [ versionId, versionTime, parameters, DIDDoc State, Data Integrity Proof ].
        When creating (registering) the DID the first entry starts with the follows items for processing:
        [ "{SCID}", "<current time>", "parameters": [ <parameters>], { "value": "<DIDDoc with Placeholders>" } ]
         */

        JsonObject genesisDidDoc = JsonParser.parseString(didDocWithSCID).getAsJsonObject();

        String genesisDidDocHashHex = JCSHasher.hashJsonObject(genesisDidDoc);

        var didLogEntryWithoutProofAndSignature = new JsonArray();

        // Add a preliminary versionId value
        // The first item in the input JSON array MUST be the placeholder string {SCID}.
        didLogEntryWithoutProofAndSignature.add(scid);
        // Add the versionTime value
        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        didLogEntryWithoutProofAndSignature.add(DateTimeFormatter.ISO_INSTANT.format(now.truncatedTo(ChronoUnit.SECONDS)));

        // Define the parameters
        // The third item in the input JSON array MUST be the parameters JSON object.
        // The parameters are used to configure the DID generation and verification processes.
        // All parameters MUST be valid and all required values in the first version of the DID MUST be present.
        JsonObject didMethodParameters = new JsonObject();
        didMethodParameters.addProperty("method", "did:tdw:0.3");
        didMethodParameters.addProperty("scid", scid);
        //didMethodParameters.addProperty("hash", null);
        // Since v0.3 (https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
        //            Removes the cryptosuite parameter, moving it to implied based on the method parameter.
        //cryptosuite: Option::None,
        //didMethodParameters.addProperty("prerotation", false);
        //next_keys: Option::None,
        //moved: Option::None,
        //deactivated: Option::None,
        //ttl: Option::None,
        didMethodParameters.addProperty("portable", false);
        didLogEntryWithoutProofAndSignature.add(didMethodParameters);

        // Add the initial DIDDoc
        // The fourth item in the input JSON array MUST be the JSON object {"value": <diddoc> }, where <diddoc> is the initial DIDDoc as described in the previous step 3.
        JsonObject initialDidDoc = new JsonObject();
        initialDidDoc.add("value", genesisDidDoc);
        didLogEntryWithoutProofAndSignature.add(initialDidDoc);

        // See https://identity.foundation/trustdidweb/v0.3/#generate-entry-hash
        // After the SCID is generated, the literal {SCID} placeholders are replaced by the generated SCID value (below).
        // This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        // Once the process has run, the version number of this first version of the DID (1),
        // a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
        String entryHash = 'Q' + Base58.encode(JCSHasher.hashJsonArray(didLogEntryWithoutProofAndSignature).getBytes(StandardCharsets.UTF_8));
        //String entryHash = 'Q' + Base58.encode(didLogEntryWithoutProofAndSignatureHash);

        /*
        https://identity.foundation/trustdidweb/v0.3/#data-integrity-proof-generation-and-first-log-entry:
        The last step in the creation of the first log entry is the generation of the data integrity proof.
        One of the keys in the updateKeys parameter MUST be used (in the form of a did:key) to generate the signature in the proof,
        with the versionId value (item 1 of the did log) used as the challenge item.
        The generated proof is added to the JSON as the fifth item, and the entire array becomes the first entry in the DID Log.
         */

        JsonObject proof = new JsonObject();
        proof.addProperty("type", "DataIntegrityProof");
        proof.addProperty("cryptoSuite", "eddsa-jcs-2022");
        //proof.addProperty("created", ZonedDateTime.now().format(DateTimeFormatter.ISO_INSTANT.withZone(ZoneId.systemDefault())));
        proof.addProperty("created", DateTimeFormatter.ISO_INSTANT.format(now.truncatedTo(ChronoUnit.SECONDS)));
        String verificationMethodString = genesisDidDoc.get("id").getAsString() + '#' + keyDefHashMultibase;
        proof.addProperty("verificationMethod", verificationMethodString);
        proof.addProperty("proofPurpose", "authentication");
        proof.addProperty("challenge", "1-" + entryHash);

        String proofHashHex = JCSHasher.hashJsonObject(proof);

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022:
        // Let hashData be the result of joining proofConfigHash (the first hash) with transformedDocumentHash (the second hash).
        String signedHashDataMultibase = 'z' + Base58.encode(this.signer.sign(proofHashHex + genesisDidDocHashHex));

        // See https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022
        proof.addProperty("proofValue", signedHashDataMultibase);

        JsonArray didLogEntryWithProof = new JsonArray();
        didLogEntryWithProof.add("1-" + entryHash);
        didLogEntryWithProof.add(didLogEntryWithoutProofAndSignature.get(1));
        didLogEntryWithProof.add(didLogEntryWithoutProofAndSignature.get(2));
        didLogEntryWithProof.add(didLogEntryWithoutProofAndSignature.get(3));
        didLogEntryWithProof.add(proof);

        if (this.signer.verify(proofHashHex + genesisDidDocHashHex, Base58.decode(signedHashDataMultibase.substring(1)))) {

            return didLogEntryWithProof.toString();
        }

        return null;
    }
}