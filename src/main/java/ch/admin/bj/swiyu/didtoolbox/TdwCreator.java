package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.Builder;
import lombok.Getter;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Map;

@Builder
@Getter
public class TdwCreator {

    private static String SCID_PLACEHOLDER = "{SCID}";

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

        /* CAUTION According to https://github.com/decentralized-identity/trustdidweb-ts/blob/main/src/utils.ts#L170
        export const createVMID = (vm: VerificationMethod, did: string | null) => {
            return `${did ?? ''}#${vm.publicKeyMultibase?.slice(-8) || nanoid(8)}`
        }
         */
        String publicKeyMultibase = this.signer.getEd25519VerificationKey2020();
        String verfificationMethodId = publicKeyMultibase.substring(publicKeyMultibase.length() - 8);

        // Create verification method for subject with placeholder
        JsonArray verificationMethod = new JsonArray();
        JsonObject verificationMethodObj = new JsonObject();
        verificationMethodObj.addProperty("id", didTDW + "#" + verfificationMethodId);
        verificationMethodObj.addProperty("controller", didTDW);
        verificationMethodObj.addProperty("type", "Ed25519VerificationKey2020");
        verificationMethodObj.addProperty("publicKeyMultibase", publicKeyMultibase);
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

                String publicKeyMultibaseProperty = publicKeyMultibase; // fallback
                if (e.getValue().getAssertionPublicKey() != null) {
                    publicKeyMultibaseProperty = e.getValue().getAssertionPublicKey();
                }
                assertionMethodObj.addProperty("publicKeyMultibase", publicKeyMultibaseProperty);

                assertionMethod.add(assertionMethodObj);
            });

            didDoc.add("assertionMethod", assertionMethod);
        }

        /*
        Generate a preliminary DID Log Entry (input JSON array)
        The DID log entry is an input JSON array that when completed contains the following items:
        [ versionId, versionTime, parameters, DIDDoc State, Data Integrity Proof ].
        When creating (registering) the DID the first entry starts with the follows items for processing:
        [ "{SCID}", "<current time>", "parameters": [ <parameters>], { "value": "<DIDDoc with Placeholders>" } ]
         */

        var didLogEntryWithoutProofAndSignature = new JsonArray();

        // Add a preliminary versionId value
        // The first item in the input JSON array MUST be the placeholder string {SCID}.
        didLogEntryWithoutProofAndSignature.add(SCID_PLACEHOLDER);
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
        didMethodParameters.addProperty("scid", SCID_PLACEHOLDER);

        /*
        Generate the authorization key pair(s) Authorized keys are authorized to control (create, update, deactivate) the DID.
        This includes generating any other key pairs that will be placed into the initial DIDDoc for the DID.

        For each authorization key pair, generate a multikey based on the key pair’s public key.
        The multikey representations of the public keys are placed in the updateKeys item in parameters.

        updateKeys: A list of one or more multikey formatted public keys associated with the private keys that are
        authorized to sign the log entries that update the DID from one version to the next. An instance of the list in
        an entry replaces the previously active list. If an entry does not have the updateKeys item,
        the currently active list continues to apply.
         */
        JsonArray updateKeys = new JsonArray();
        updateKeys.add(this.signer.getEd25519VerificationKey2020());
        didMethodParameters.add("updateKeys", updateKeys);

        // Since v0.3 (https://identity.foundation/trustdidweb/v0.3/#didtdw-version-changelog):
        //            Removes the cryptosuite parameter, moving it to implied based on the method parameter.
        //cryptosuite: Option::None,
        didMethodParameters.addProperty("prerotation", false);
        // OPTIONAL: next_keys, moved, deactivated, ttl
        didMethodParameters.addProperty("portable", false);
        didLogEntryWithoutProofAndSignature.add(didMethodParameters);

        // Generate SCID and replace placeholder in did doc
        var scid = JCSHasher.buildSCID(didLogEntryWithoutProofAndSignature);

        /* https://identity.foundation/trustdidweb/v0.3/#output-of-the-scid-generation-process:
        After the SCID is generated, the literal {SCID} placeholders are replaced by the generated SCID value (below).
        This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        Once the process has run, the version number of this first version of the DID (1),
        a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
         */

        // CAUTION "\\" prevents "java.util.regex.PatternSyntaxException: Illegal repetition near index 1"
        String didDocWithSCID = didDoc.toString().replaceAll("\\" + SCID_PLACEHOLDER, scid);
        didDoc = JsonParser.parseString(didDocWithSCID).getAsJsonObject();

        // Add the initial DIDDoc
        // The fourth item in the input JSON array MUST be the JSON object {"value": <diddoc> }, where <diddoc> is the initial DIDDoc as described in the previous step 3.
        JsonObject initialDidDoc = new JsonObject();
        initialDidDoc.add("value", didDoc);
        didLogEntryWithoutProofAndSignature.add(initialDidDoc);

        // CAUTION "\\" prevents "java.util.regex.PatternSyntaxException: Illegal repetition near index 1"
        String didLogEntryWithoutProofAndSignatureWithSCID = didLogEntryWithoutProofAndSignature.toString().replaceAll("\\" + SCID_PLACEHOLDER, scid);
        JsonArray didLogEntryWithSCIDWithoutProofAndSignature = JsonParser.parseString(didLogEntryWithoutProofAndSignatureWithSCID).getAsJsonArray();

        // See https://identity.foundation/trustdidweb/v0.3/#generate-entry-hash
        // After the SCID is generated, the literal {SCID} placeholders are replaced by the generated SCID value (below).
        // This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        // Once the process has run, the version number of this first version of the DID (1),
        // a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
        String entryHash = JCSHasher.buildSCID(didLogEntryWithSCIDWithoutProofAndSignature);

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
        proof.addProperty("created", DateTimeFormatter.ISO_INSTANT.format(now.truncatedTo(ChronoUnit.SECONDS)));

        /*
        The data integrity proof verificationMethod is the did:key from the first log entry, and the challenge is the versionId from this log entry.
         */
        proof.addProperty("verificationMethod", "did:key:" + this.signer.getEd25519VerificationKey2020() + '#' + this.signer.getEd25519VerificationKey2020());
        proof.addProperty("proofPurpose", "authentication");
        proof.addProperty("challenge", "1-" + entryHash);

        // See https://www.w3.org/TR/vc-di-eddsa/#hashing-eddsa-jcs-2022:
        // Let hashData be the result of joining proofConfigHash (the first hash) with transformedDocumentHash (the second hash).
        String proofValue = JCSHasher.buildProof(proof, didDoc, this.signer);

        // See https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022
        proof.addProperty("proofValue", proofValue);

        JsonArray didLogEntryWithProof = new JsonArray();
        didLogEntryWithProof.add("1-" + entryHash);
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(1));
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(2));
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(3));
        didLogEntryWithProof.add(proof);

        return didLogEntryWithProof.toString();
    }
}