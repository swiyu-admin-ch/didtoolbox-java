package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.Builder;
import lombok.Getter;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Map;

@Builder
@Getter
public class TdwCreator {

    private static String SCID_PLACEHOLDER = "{SCID}";

    private Map<String, String> assertionMethodKeys;
    private Map<String, String> authenticationKeys;
    private Ed25519SignerVerifier signer;
    // TODO private File dirToStoreKeyPair;

    /**
     * Creates a did:tdw DID Document.
     *
     * @param identifierRegistryUrl (of a did.jsonl) in its entirety w.r.t. https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation
     * @return
     * @throws IOException
     */
    public String create(URL identifierRegistryUrl) throws IOException {
        return create(identifierRegistryUrl, ZonedDateTime.now());
    }

    private JsonObject buildVerificationMethodWithPublicKeyJwk(String didTDW, String keyID, String jwk, File jwksFile) throws IOException {

        String publicKeyJwk = jwk;
        if (publicKeyJwk == null || publicKeyJwk.isEmpty()) {
            publicKeyJwk = JwkUtils.generateEC(keyID, jwksFile);
        }

        JsonObject verificationMethodObj = new JsonObject();
        verificationMethodObj.addProperty("id", didTDW + "#" + keyID);
        verificationMethodObj.addProperty("controller", didTDW);
        verificationMethodObj.addProperty("type", "JsonWebKey2020");
        //verificationMethodObj.addProperty("publicKeyMultibase", publicKeyMultibase);
        verificationMethodObj.add("publicKeyJwk", JsonParser.parseString(publicKeyJwk).getAsJsonObject());

        return verificationMethodObj;
    }

    /**
     * Creates a did:tdw DID Document for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param identifierRegistryUrl (of a did.jsonl) in its entirety w.r.t. https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation
     * @param now
     * @return
     * @throws IOException
     */
    String create(URL identifierRegistryUrl, ZonedDateTime now) throws IOException {

        // Method-Specific Identifier: https://identity.foundation/didwebvh/v0.3/#method-specific-identifier
        // W.r.t. https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation
        // See also https://identity.foundation/didwebvh/v0.3/#example-7
        String didTDW = "did:tdw:{SCID}:" + identifierRegistryUrl.getHost();
        int port = identifierRegistryUrl.getPort(); // the port number, or -1 if the port is not set
        if (port != -1) {
            didTDW += "%3A" + port;
        }
        String path = identifierRegistryUrl.getPath(); // the path part of this URL, or an empty string if one does not exist
        if (!path.isEmpty()) {
            didTDW += path.replace("/did.jsonl", "") // cleanup
                    .replaceAll("/", ":"); // w.r.t. https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation
        }

        var context = new JsonArray();
        context.add("https://www.w3.org/ns/did/v1");
        context.add("https://w3id.org/security/suites/jws-2020/v1"); // because of the format of generated authentication/assertionMethod keys (JsonWebKey2020)

        // Create initial did doc with placeholder
        var didDoc = new JsonObject();
        didDoc.add("@context", context);
        didDoc.addProperty("id", didTDW);
        // "controller" is omitted w.r.t. https://jira.bit.admin.ch/browse/EIDSYS-352
        //didDoc.addProperty("controller", didTDW);

        JsonArray verificationMethod = new JsonArray();

        if (this.authenticationKeys != null && !this.authenticationKeys.isEmpty()) {

            JsonArray authentication = new JsonArray();
            for (var key : this.authenticationKeys.entrySet()) {
                authentication.add(didTDW + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, key.getKey(), key.getValue(), null));
            }

            didDoc.add("authentication", authentication);

        } else {

            var outputDir = new File(".didtoolbox");
            if (!outputDir.exists()) {
                outputDir.mkdirs();
            }
            verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, "auth-key-01", null, new File(outputDir, "auth-key-01"))); // default

            JsonArray authentication = new JsonArray();
            authentication.add(didTDW + "#" + "auth-key-01");
            didDoc.add("authentication", authentication);
        }

        if (this.assertionMethodKeys != null && !this.assertionMethodKeys.isEmpty()) {

            JsonArray assertionMethod = new JsonArray();
            for (var key : this.assertionMethodKeys.entrySet()) {
                assertionMethod.add(didTDW + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, key.getKey(), key.getValue(), null));
            }

            didDoc.add("assertionMethod", assertionMethod);

        } else {

            var outputDir = new File(".didtoolbox");
            if (!outputDir.exists()) {
                outputDir.mkdirs();
            }
            verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, "assert-key-01", null, new File(outputDir, "assert-key-01"))); // default

            JsonArray assertionMethod = new JsonArray();
            assertionMethod.add(didTDW + "#" + "assert-key-01");
            didDoc.add("assertionMethod", assertionMethod);
        }

        didDoc.add("verificationMethod", verificationMethod);

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
        updateKeys.add(this.signer.getVerificationKeyMultibase());
        didMethodParameters.add("updateKeys", updateKeys);

        /* See https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters
        didMethodParameters.add("nextKeyHashes", new JsonArray());
        didMethodParameters.add("witnesses", new JsonArray());
        didMethodParameters.addProperty("witnessThreshold", 0);
        didMethodParameters.addProperty("deactivated", false);
        didMethodParameters.addProperty("portable", false);
        didMethodParameters.addProperty("prerotation", false);
         */

        // Since v0.3 (https://identity.foundation/didwebvh/v0.3/#didtdw-version-changelog):
        //            Removes the cryptosuite parameter, moving it to implied based on the method parameter.
        //cryptosuite: Option::None,

        didLogEntryWithoutProofAndSignature.add(didMethodParameters);

        // Add the initial DIDDoc
        // The fourth item in the input JSON array MUST be the JSON object {"value": <diddoc> }, where <diddoc> is the initial DIDDoc as described in the previous step 3.
        JsonObject initialDidDoc = new JsonObject();
        initialDidDoc.add("value", didDoc);
        didLogEntryWithoutProofAndSignature.add(initialDidDoc);

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

        // CAUTION "\\" prevents "java.util.regex.PatternSyntaxException: Illegal repetition near index 1"
        String didLogEntryWithoutProofAndSignatureWithSCID = didLogEntryWithoutProofAndSignature.toString().replaceAll("\\" + SCID_PLACEHOLDER, scid);
        JsonArray didLogEntryWithSCIDWithoutProofAndSignature = JsonParser.parseString(didLogEntryWithoutProofAndSignatureWithSCID).getAsJsonArray();

        // See https://identity.foundation/didwebvh/v0.3/#generate-entry-hash
        // After the SCID is generated, the literal {SCID} placeholders are replaced by the generated SCID value (below).
        // This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        // Once the process has run, the version number of this first version of the DID (1),
        // a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
        String entryHash = JCSHasher.buildSCID(didLogEntryWithSCIDWithoutProofAndSignature);

        JsonArray didLogEntryWithProof = new JsonArray();
        didLogEntryWithProof.add("1-" + entryHash);
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(1));
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(2));
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(3));

        /*
        https://identity.foundation/trustdidweb/v0.3/#data-integrity-proof-generation-and-first-log-entry:
        The last step in the creation of the first log entry is the generation of the data integrity proof.
        One of the keys in the updateKeys parameter MUST be used (in the form of a did:key) to generate the signature in the proof,
        with the versionId value (item 1 of the did log) used as the challenge item.
        The generated proof is added to the JSON as the fifth item, and the entire array becomes the first entry in the DID Log.
         */
        JsonArray proofs = new JsonArray();
        proofs.add(JCSHasher.buildDataIntegrityProof(didDoc, false, this.signer, 1, entryHash, "authentication", now));
        didLogEntryWithProof.add(proofs);

        return didLogEntryWithProof.toString();
    }
}