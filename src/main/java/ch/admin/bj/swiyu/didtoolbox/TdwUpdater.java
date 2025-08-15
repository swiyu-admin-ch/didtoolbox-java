package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.DidLogMeta;
import ch.admin.bj.swiyu.didtoolbox.model.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.model.TdwDidLogMetaPeeker;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import ch.admin.eid.didtoolbox.DidDoc;
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
import java.nio.file.Files;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;

/**
 * {@link TdwUpdater} is the class in charge of <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log update (rotate).
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@link #builder()} method.
 * <p>
 * Once a {@link TdwUpdater} object is "built", creating a <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a>
 * log goes simply by calling {@link #update(String)} method. Optionally, but most likely, an already existing key material will
 * be also used in the process, so for the purpose there are further fluent methods available:
 * <ul>
 * <li>{@link TdwUpdaterBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} for setting the update (Ed25519) key</li>
 * <li>{@link TdwUpdaterBuilder#authenticationKeys(Map)} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link TdwUpdaterBuilder#assertionMethodKeys(Map)} for setting/assertion
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
 *         String initialDidLogEntryWithGeneratedKeys = null;
 *         String updatedDidLogEntryWithReplacedVerificationMaterial = null;
 *         try {
 *             URL identifierRegistryUrl = URL.of(new URI("https://127.0.0.1:54858/123456789/123456789/did.jsonl"), null);
 *             var verificationMethodKeyProvider = new Ed25519VerificationMethodKeyProviderImpl(new File("src/test/data/private.pem"), new File("src/test/data/public.pem"));
 *
 *             // NOTE that all verification material will be generated here as well
 *             initialDidLogEntryWithGeneratedKeys = TdwCreator.builder()
 *                 .verificationMethodKeyProvider(verificationMethodKeyProvider)
 *                 .build()
 *                 .create(identifierRegistryUrl);
 *
 *             // Now update the previously generated initial single-entry DID log
 *             updatedDidLogEntryWithReplacedVerificationMaterial = TdwUpdater.builder()
 *                 .verificationMethodKeyProvider(verificationMethodKeyProvider) // the same used during creation
 *                 .assertionMethodKeys(Map.of(
 *                     "my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01")
 *                 ))
 *                 .authenticationKeys(Map.of(
 *                     "my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01")
 *                 ))
 *                 .build()
 *                 .update(initialDidLogEntryWithGeneratedKeys);
 *
 *         } catch (Exception e) {
 *             // some exc. handling goes here
 *             System.exit(1);
 *         }
 *
 *         // do something with the initialDidLogEntryWithGeneratedKeys/updatedDidLogEntryWithReplacedVerificationMaterial vars here
 *     }
 * }
 * </pre>
 */
@Builder
@Getter
public class TdwUpdater {

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

    private static JsonObject buildVerificationMethodWithPublicKeyJwk(String didTDW, String keyID, String publicKeyJwk) throws TdwUpdaterException {

        JsonObject verificationMethodObj = new JsonObject();
        verificationMethodObj.addProperty("id", didTDW + "#" + keyID);
        // CAUTION The "controller" property must not be present w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDSYS-35
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
     * Updates a valid <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log by taking into account other
     * features of this {@link TdwUpdater} object, optionally customized by previously calling fluent methods like
     * {@link TdwUpdaterBuilder#verificationMethodKeyProvider}, {@link TdwUpdaterBuilder#authenticationKeys(Map)} or
     * {@link TdwUpdaterBuilder#assertionMethodKeys(Map)}.
     *
     * @param didLog to update. Expected to be resolvable/verifiable already.
     * @return a whole new <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log entry to be appended to the existing {@code didLog}
     * @throws TdwUpdaterException if update fails for whatever reason.
     * @see #update(String, ZonedDateTime)
     */
    public String update(String didLog) throws TdwUpdaterException {
        return update(didLog, ZonedDateTime.now());
    }

    /**
     * The file-system-as-input variation of {@link #update(String)}
     *
     * @throws TdwUpdaterException if update fails for whatever reason
     * @throws IOException         if an I/ O error occurs reading from the file or a malformed or unmappable byte sequence is read
     * @see #update(String)
     */
    String update(File didLogFile) throws TdwUpdaterException, IOException {
        return update(Files.readString(didLogFile.toPath()), ZonedDateTime.now());
    }

    /**
     * Updates a <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <p>
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param didLog to update. Expected to be resolvable/verifiable already.
     * @param zdt    a date-time with a time-zone in the ISO-8601 calendar system
     * @return a whole new  <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log entry to be appended to the existing {@code didLog}
     * @throws TdwUpdaterException if update fails for whatever reason.
     */
    String update(String didLog, ZonedDateTime zdt) throws TdwUpdaterException {

        DidLogMeta didLogMeta;
        String didTDW;
        DidDoc oldDidDoc;
        Did did = null;
        try {
            didLogMeta = TdwDidLogMetaPeeker.peek(didLog); // try extracting DID doc ID
            didTDW = didLogMeta.getDidDocId();

            // According to https://identity.foundation/didwebvh/v0.3/#update-rotate:
            // To update a DID, a new, verifiable DID Log Entry must be generated, witnessed (if necessary),
            // appended to the existing DID Log (did.jsonl), and published to the web location defined by the DID.
            did = new Did(didTDW);
            oldDidDoc = did.resolve(didLog);

        } catch (DidResolveException | DidLogMetaPeekerException e) {
            throw new TdwUpdaterException("Unresolvable/unverifiable DID log detected", e);
        } finally {
            if (did != null) {
                did.close();
            }
        }

        // CAUTION Only activated DIDs can be updated
        if (didLogMeta.getParams().getDeactivated() != null && didLogMeta.getParams().getDeactivated()) {
            throw new TdwUpdaterException("DID already deactivated");
        }

        if (!this.verificationMethodKeyProvider.isKeyMultibaseInSet(didLogMeta.getParams().getUpdateKeys())) {
            throw new TdwUpdaterException("Update key mismatch");
        }

        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        //
        // The versionTime for each log entry MUST be greater than the previous entry’s time.
        // The versionTime of the last entry MUST be earlier than the current time.
        var lastEntryDateTime = ZonedDateTime.parse(didLogMeta.getDateTime());
        if (zdt.isBefore(lastEntryDateTime) || zdt.isEqual(lastEntryDateTime)) {
            throw new TdwUpdaterException("The versionTime of the last entry MUST be earlier than the current time");
        }

        // Create initial did doc with placeholder
        var didDoc = new JsonObject();

        // take over context
        var context = new JsonArray();
        for (var ctx : oldDidDoc.getContext()) {
            context.add(ctx);
        }
        didDoc.add("@context", context);

        didDoc.addProperty("id", didTDW);
        // CAUTION "controller" property is omitted w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDSYS-352
        // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
        //didDoc.addProperty("controller", didTDW);

        if ((this.authenticationKeys == null || this.authenticationKeys.isEmpty())
                && (this.assertionMethodKeys == null || this.assertionMethodKeys.isEmpty())) {
            throw new TdwUpdaterException("No update will take place as no verification material is supplied whatsoever");
        }

        var verificationMethod = new JsonArray();

        if (this.authenticationKeys != null && !this.authenticationKeys.isEmpty()) {

            JsonArray authentication = new JsonArray();
            for (var key : this.authenticationKeys.entrySet()) {

                authentication.add(didTDW + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, key.getKey(), key.getValue()));
            }

            didDoc.add("authentication", authentication);
        }

        if (this.assertionMethodKeys != null && !this.assertionMethodKeys.isEmpty()) {

            JsonArray assertionMethod = new JsonArray();
            for (var key : this.assertionMethodKeys.entrySet()) {

                assertionMethod.add(didTDW + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, key.getKey(), key.getValue()));
            }

            didDoc.add("assertionMethod", assertionMethod);
        }

        // NOTE that there is no need to add the rest of the existing (verification method) keys, as they can be
        //      added, if required, at any point again

        didDoc.add("verificationMethod", verificationMethod);

        // The DID log entry is an input JSON array that when completed contains the following items:
        // [ versionId, versionTime, parameters, DIDDoc State, Data Integrity Proof ].

        var didLogEntryWithoutProofAndSignature = new JsonArray();

        // https://identity.foundation/didwebvh/v0.3/#entry-hash-generation-and-verification:
        // For the first log entry, the predecessor versionId is the SCID (itself a hash),
        // while for all other entries it is the versionId item from the previous log entry.
        didLogEntryWithoutProofAndSignature.add(didLogMeta.getLastVersionId());

        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        //
        // The versionTime for each log entry MUST be greater than the previous entry’s time.
        // The versionTime of the last entry MUST be earlier than the current time.
        didLogEntryWithoutProofAndSignature.add(DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));

        // The third item in the input JSON array MUST be the parameters JSON object.
        // The parameters are used to configure the DID generation and verification processes.
        // All parameters MUST be valid and all required values in the first version of the DID MUST be present.

        if (this.updateKeys != null) {

            var updateKeysJsonArray = new JsonArray();

            var newUpdateKeys = Set.of(this.updateKeys.stream().map(file -> {
                try {
                    return PemUtils.parsePEMFilePublicKeyEd25519Multibase(file);
                } catch (Exception ignore) {
                }
                return null;
            }).toArray(String[]::new));

            if (!didLogMeta.getParams().getUpdateKeys().containsAll(newUpdateKeys)) { // need for change?

                String updateKey;
                for (var pemFile : this.updateKeys) {
                    try {
                        updateKey = PemUtils.parsePEMFilePublicKeyEd25519Multibase(pemFile);
                    } catch (Exception e) {
                        throw new TdwUpdaterException(e);
                    }

                    // it is a distinct list of keys, after all
                    if (!updateKeysJsonArray.contains(new JsonPrimitive(updateKey))) {
                        updateKeysJsonArray.add(updateKey);
                    }
                }
            }

            // Define the parameters (https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters)
            // The third item in the input JSON array MUST be the parameters JSON object.
            // The parameters are used to configure the DID generation and verification processes.
            // All parameters MUST be valid and all required values in the first version of the DID MUST be present.
            var didMethodParameters = new JsonObject();
            if (!updateKeysJsonArray.isEmpty()) {
                didMethodParameters.add("updateKeys", updateKeysJsonArray);
            }

            didLogEntryWithoutProofAndSignature.add(didMethodParameters);

        } else {
            didLogEntryWithoutProofAndSignature.add(new JsonObject()); // CAUTION params remain the same
        }

        // The fourth item in the input JSON array MUST be the JSON object {"value": <diddoc> }, where <diddoc> is the initial DIDDoc as described in the previous step 3.
        var didDocJson = new JsonObject();
        didDocJson.add("value", didDoc);
        didLogEntryWithoutProofAndSignature.add(didDocJson);

        // See https://identity.foundation/didwebvh/v0.3/#generate-entry-hash
        // This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        // Once the process has run, the version number of this first version of the DID (1),
        // a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
        String entryHash = null;
        try {
            entryHash = JCSHasher.buildSCID(didLogEntryWithoutProofAndSignature.toString());
        } catch (IOException e) {
            throw new TdwUpdaterException(e);
        }

        JsonArray didLogEntryWithProof = new JsonArray();
        var challenge = didLogMeta.getLastVersionNumber() + 1 + "-" + entryHash; // versionId as the proof challenge
        didLogEntryWithProof.add(challenge);
        didLogEntryWithProof.add(didLogEntryWithoutProofAndSignature.get(1));
        didLogEntryWithProof.add(didLogEntryWithoutProofAndSignature.get(2));
        didLogEntryWithProof.add(didLogEntryWithoutProofAndSignature.get(3));

        /*
        https://identity.foundation/didwebvh/v0.3/#data-integrity-proof-generation-and-first-log-entry:
        The last step in the creation of the first log entry is the generation of the data integrity proof.
        One of the keys in the updateKeys parameter MUST be used (in the form of a did:key) to generate the signature in the proof,
        with the versionId value (item 1 of the did log) used as the challenge item.
        The generated proof is added to the JSON as the fifth item, and the entire array becomes the first entry in the DID Log.
         */
        var proofs = new JsonArray();
        JsonObject proof = null;
        try {
            proof = JCSHasher.buildDataIntegrityProof(didDoc, false, this.verificationMethodKeyProvider, challenge, "authentication", zdt);
        } catch (IOException e) {
            throw new TdwUpdaterException("Fail to build DID doc data integrity proof", e);
        }
        // CAUTION Set proper "verificationMethod"
        proof.addProperty("verificationMethod", "did:key:" + this.verificationMethodKeyProvider.getVerificationKeyMultibase() + '#' + this.verificationMethodKeyProvider.getVerificationKeyMultibase());
        proofs.add(proof);
        didLogEntryWithProof.add(proofs);

        did = new Did(didLogMeta.getDidDocId());
        try {
            // NOTE Enforcing DID log conformity by calling:
            //      ch.admin.eid.didtoolbox.DidLogEntryValidator.Companion
            //          .from(DidLogEntryJsonSchema.V03_EID_CONFORM)
            //          .validate(didLogEntryWithProof.toString());
            //      would not be necessary here, as it is already part of the `resolve` method.
            // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
            did.resolve(new StringBuilder(didLog.trim()).append(System.lineSeparator()).append(didLogEntryWithProof).toString()); // sanity check
        } catch (DidResolveException e) {
            throw new RuntimeException("Updating the DID log resulted in unresolvable/unverifiable DID log", e);
        } finally {
            did.close();
        }

        return didLogEntryWithProof.toString();
    }
}