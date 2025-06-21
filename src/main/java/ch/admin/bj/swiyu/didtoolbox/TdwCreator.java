package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.URL;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.security.spec.InvalidKeySpecException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;

/**
 * {@link TdwCreator} is the class in charge of <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log generation.
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@link #builder()} method.
 * <p>
 * Once a {@link TdwCreator} object is "built", creating a <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a>
 * log goes simply by calling {@link #create(URL)} method. Optionally, but most likely, an already existing key material will
 * be also used in the process, so for the purpose there are further fluent methods available:
 * <ul>
 * <li>{@link TdwCreator.TdwCreatorBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} for setting the update (Ed25519) key</li>
 * <li>{@link TdwCreator.TdwCreatorBuilder#authenticationKeys(Map)} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link TdwCreator.TdwCreatorBuilder#assertionMethodKeys(Map)} for setting/assertion
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * </ul>
 * To load keys from the file system, the following helpers are available:
 * <ul>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(Reader, Reader)} for loading the update (Ed25519) key from
 * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> files</li>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(InputStream, String, String, String)} for loading the update (Ed25519) key from Java KeyStore (JKS) files</li>
 * <li>{@link JwkUtils#loadECPublicJWKasJSON(File, String)} for loading authentication/assertion public
 * EC P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a> keys from
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">PEM</a> files</li>
 * </ul>
 * For instance:
 * <pre>
 * {@code
 *     package mypackage;
 *
 *     import ch.admin.bj.swiyu.didtoolbox.*;
 *     import java.net.*;
 *
 *     public static void main(String... args) {
 *
 *         String didLogEntryWithGeneratedKeys = null;
 *         String didLogEntryWithExternalKeys = null;
 *         try {
 *             URL identifierRegistryUrl = URL.of(new URI("https://127.0.0.1:54858/123456789/123456789/did.jsonl"), null);
 *
 *             // NOTE that all required keys will be generated here as well, as no explicit verificationMethodKeyProvider is set
 *             didLogEntryWithGeneratedKeys = TdwCreator.builder()
 *                 .build()
 *                 .create(identifierRegistryUrl);
 *
 *             // Using already existing key material
 *             didLogEntryWithExternalKeys = TdwCreator.builder()
 *                 .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new File("private-key.pem"), new File("public-key.pem")))
 *                 .assertionMethodKeys(Map.of(
 *                     "my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("assert-key-01.pub"), "my-assert-key-01")
 *                 ))
 *                 .authenticationKeys(Map.of(
 *                     "my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("auth-key-01.pub"), "my-auth-key-01")
 *                 ))
 *                 .build()
 *                 .create(identifierRegistryUrl);
 *
 *         } catch (Exception e) {
 *             // some exc. handling goes here
 *             System.exit(1);
 *         }
 *
 *         // do something with the didLogEntry* vars here
 *     }
 * }
 * </pre>
 */
@Builder
@Getter
public class TdwCreator {

    private static String SCID_PLACEHOLDER = "{SCID}";

    @Getter(AccessLevel.PRIVATE)
    private Map<String, String> assertionMethodKeys;
    @Getter(AccessLevel.PRIVATE)
    private Map<String, String> authenticationKeys;
    @Builder.Default
    @Getter(AccessLevel.PRIVATE)
    private VerificationMethodKeyProvider verificationMethodKeyProvider = new Ed25519VerificationMethodKeyProviderImpl();
    @Getter(AccessLevel.PRIVATE)
    private Set<File> updateKeys;
    // TODO private File dirToStoreKeyPair;
    @Getter(AccessLevel.PRIVATE)
    private boolean forceOverwrite;

    /**
     * Creates a valid <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log by taking into account other
     * features of this {@link TdwCreator} object, optionally customized by previously calling fluent methods like
     * {@link TdwCreator.TdwCreatorBuilder#verificationMethodKeyProvider}, {@link TdwCreator.TdwCreatorBuilder#authenticationKeys(Map)} or
     * {@link TdwCreator.TdwCreatorBuilder#assertionMethodKeys(Map)}.
     *
     * @param identifierRegistryUrl is the URL of a did.jsonl in its entirety w.r.t.
     *                              <a href="https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation">he-did-to-https-transformation</a>
     * @return a valid <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log
     * @throws IOException if creation fails for whatever reason
     * @see #create(URL, ZonedDateTime)
     */
    public String create(URL identifierRegistryUrl) throws IOException {
        return create(identifierRegistryUrl, ZonedDateTime.now());
    }

    private JsonObject buildVerificationMethodWithPublicKeyJwk(String didTDW, String keyID, String jwk, File jwksFile) throws IOException {

        String publicKeyJwk = jwk;
        if (publicKeyJwk == null || publicKeyJwk.isEmpty()) {
            publicKeyJwk = JwkUtils.generatePublicEC256(keyID, jwksFile, this.forceOverwrite);
        }

        JsonObject verificationMethodObj = new JsonObject();
        verificationMethodObj.addProperty("id", didTDW + "#" + keyID);
        // CAUTION The "controller" property must not be present w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDSYS-352
        // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
        //verificationMethodObj.addProperty("controller", didTDW);
        verificationMethodObj.addProperty("type", "JsonWebKey2020");
        // CAUTION The "publicKeyMultibase" property must not be present w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDOMNI-35
        // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
        //verificationMethodObj.addProperty("publicKeyMultibase", publicKeyMultibase);
        verificationMethodObj.add("publicKeyJwk", JsonParser.parseString(publicKeyJwk).getAsJsonObject());

        return verificationMethodObj;
    }

    /**
     * Creates a <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <p>
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param identifierRegistryUrl (of a did.jsonl) in its entirety w.r.t.
     *                              <a href="https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation">the-did-to-https-transformation</a>
     * @param zdt                   a date-time with a time-zone in the ISO-8601 calendar system
     * @return
     * @throws IOException
     */
    String create(URL identifierRegistryUrl, ZonedDateTime zdt) throws IOException {

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
        // See "Swiss e-ID and trust infrastructure: Interoperability profile" available at:
        //     https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#did-document-format
        context.add("https://www.w3.org/ns/did/v1");
        context.add("https://w3id.org/security/jwk/v1");

        // Create initial did doc with placeholder
        var didDoc = new JsonObject();
        didDoc.add("@context", context);
        didDoc.addProperty("id", didTDW);
        // CAUTION The "controller" property must not be present w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDSYS-352
        // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
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

            var outputDir = createPrivateKeyDirectoryIfDoesNotExist(".didtoolbox");
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

            var outputDir = createPrivateKeyDirectoryIfDoesNotExist(".didtoolbox");
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
        didLogEntryWithoutProofAndSignature.add(DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));

        // Define the parameters (https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters)
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
        var updateKeysJsonArray = new JsonArray();
        updateKeysJsonArray.add(this.verificationMethodKeyProvider.getVerificationKeyMultibase()); // first and foremost...
        if (this.updateKeys != null) {
            for (var pemFile : this.updateKeys) { // ...and then add the rest, if any
                String updateKey;
                try {
                    updateKey = PemUtils.parsePEMFilePublicKeyEd25519Multibase(pemFile);
                } catch (InvalidKeySpecException e) {
                    throw new IOException(e);
                }

                if (!updateKeysJsonArray.contains(new JsonPrimitive(updateKey))) { // it is a distinct list of keys, after all
                    updateKeysJsonArray.add(updateKey);
                }
            }
        }
        didMethodParameters.add("updateKeys", updateKeysJsonArray);

        // MUST set portable to false in the first DID log entry.
        // See "Swiss e-ID and trust infrastructure: Interoperability profile" available at:
        //     https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#didtdwdidwebvh
        didMethodParameters.addProperty("portable", false);

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
        var scid = JCSHasher.buildSCID(didLogEntryWithoutProofAndSignature.toString());

        /* https://identity.foundation/didwebvh/v0.3/#output-of-the-scid-generation-process:
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
        String entryHash = JCSHasher.buildSCID(didLogEntryWithSCIDWithoutProofAndSignature.toString());

        JsonArray didLogEntryWithProof = new JsonArray();
        var challenge = "1-" + entryHash; // versionId as the proof challenge
        didLogEntryWithProof.add(challenge);
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(1));
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(2));
        didLogEntryWithProof.add(didLogEntryWithSCIDWithoutProofAndSignature.get(3));

        /*
        https://identity.foundation/didwebvh/v0.3/#data-integrity-proof-generation-and-first-log-entry:
        The last step in the creation of the first log entry is the generation of the data integrity proof.
        One of the keys in the updateKeys parameter MUST be used (in the form of a did:key) to generate the signature in the proof,
        with the versionId value (item 1 of the did log) used as the challenge item.
        The generated proof is added to the JSON as the fifth item, and the entire array becomes the first entry in the DID Log.
         */
        JsonArray proofs = new JsonArray();
        proofs.add(JCSHasher.buildDataIntegrityProof(didDoc, false, this.verificationMethodKeyProvider, challenge, "authentication", zdt));
        didLogEntryWithProof.add(proofs);

        Did did = null;
        try {
            did = new Did(DidLogMetaPeeker.peek(didLogEntryWithProof.toString()).didDocId);
            // NOTE Enforcing DID log conformity by calling:
            //      ch.admin.eid.didtoolbox.DidLogEntryValidator.Companion
            //          .from(DidLogEntryJsonSchema.V03_EID_CONFORM)
            //          .validate(didLogEntryWithProof.toString());
            //      would not be necessary here, as it is already part of the `resolve` method.
            did.resolve(didLogEntryWithProof.toString()); // sanity check
        } catch (DidResolveException | DidLogMetaPeekerException e) {
            throw new RuntimeException("Creating a DID log resulted in unresolvable/unverifiable DID log", e);
        } finally {
            if (did != null) {
                did.close();
            }
        }

        return didLogEntryWithProof.toString();
    }

    private static File createPrivateKeyDirectoryIfDoesNotExist(String pathname) throws IOException {
        var outputDir = new File(pathname);
        if (!outputDir.exists()) {
            try {
                return FilesPrivacy.createPrivateDirectory(outputDir.toPath(), false).toFile(); // may throw DirectoryNotEmptyException, SecurityException etc.
            } catch (DirectoryNotEmptyException | FileAlreadyExistsException ex) {
                throw new RuntimeException(ex);
            } catch (AccessDeniedException ex) {
                throw new AccessDeniedException("Access denied to " + outputDir.getPath() + " due to: " + ex.getMessage());
            } catch (Throwable thr) {
                throw new IOException("Failed to create private directory " + pathname + " due to: " + thr.getMessage());
            }
        }

        return outputDir;
    }
}