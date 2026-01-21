package ch.admin.bj.swiyu.didtoolbox.webvh;

import ch.admin.bj.swiyu.didtoolbox.*;
import ch.admin.bj.swiyu.didtoolbox.context.*;
import ch.admin.bj.swiyu.didtoolbox.model.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.model.NamedDidMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.JcsSha256Hasher;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * {@link WebVerifiableHistoryUpdater} is a {@link DidLogUpdaterStrategy} implementation in charge of
 * <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log update (rotate).
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@link #builder()} method.
 * <p>
 * Once a {@link WebVerifiableHistoryUpdater} object is "built", creating a <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>
 * log goes simply by calling {@link #updateDidLog(String)} method. Optionally, but most likely, an already existing key material will
 * be also used in the process, so for the purpose there are further fluent methods available:
 * <ul>
 * <li>{@link WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder#cryptographicSuite(VcDataIntegrityCryptographicSuite)} for the purpose of adding data integrity proof</li>
 * <li>{@link WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder#authenticationKeys(Map)} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder#assertionMethodKeys(Map)} for setting/assertion
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * </ul>
 * To load required (Ed25519) keys (e.g. from the file system in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format),
 * feel free to explore all available {@link VerificationMethodKeyProvider} implementations.
 * <p>
 * To load authentication/assertion public EC P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a> keys from
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">PEM</a> files, you may rely on {@link JwkUtils}.
 * <p>
 * <p>
 * <strong>CAUTION</strong> Any explicit use of this class in your code is HIGHLY INADVISABLE.
 * Instead, rather rely on the designated {@link DidLogUpdaterContext} for the purpose. Needless to say,
 * the proper DID method must be supplied to the strategy - for that matter, simply use one of the available helpers like
 * {@link DidMethodEnum#detectDidMethod(String)} or {@link DidMethodEnum#detectDidMethod(File)}.
 * <p>
 */
@SuppressWarnings({"PMD.GodClass", "PMD.CyclomaticComplexity"})
@Builder
@Getter
public class WebVerifiableHistoryUpdater extends AbstractDidLogEntryBuilder implements DidLogUpdaterStrategy {

    private static final String SCID_PLACEHOLDER = "{SCID}";

    @Getter(AccessLevel.PRIVATE)
    private Map<String, String> assertionMethodKeys;
    @Getter(AccessLevel.PRIVATE)
    private Map<String, String> authenticationKeys;
    /**
     * Replaces the depr. {@link #verificationMethodKeyProvider},
     * but gets no precedence over it (if both called against the same object).
     */
    @Builder.Default
    @Getter(AccessLevel.PRIVATE)
    private VcDataIntegrityCryptographicSuite cryptographicSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
    /**
     * @deprecated Use {@link #cryptographicSuite} instead. Since 1.8.0
     */
    @Getter(AccessLevel.PRIVATE)
    @Deprecated
    private VcDataIntegrityCryptographicSuite verificationMethodKeyProvider;
    @Getter(AccessLevel.PRIVATE)
    private Set<File> updateKeys;
    /**
     * As specified by <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">didwebvh-did-method-parameters</a>, that is:
     * <ul>
     * <li><pre>
     * Once the nextKeyHashes parameter has been set to a non-empty array, Key Pre-Rotation is active.
     * </pre></li>
     * <li><pre>
     * The value of nextKeyHashes MAY be set to an empty array ([]) to deactivate pre-rotation.
     * </pre></li>
     * </ul>
     *
     * @deprecated
     */
    @Deprecated
    @Getter(AccessLevel.PRIVATE)
    private Set<File> nextUpdateKeys;
    /**
     * As specified by <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">didwebvh-did-method-parameters</a>, that is:
     * <ul>
     * <li><pre>
     * Once the nextKeyHashes parameter has been set to a non-empty array, Key Pre-Rotation is active.
     * </pre></li>
     * <li><pre>
     * The value of nextKeyHashes MAY be set to an empty array ([]) to deactivate pre-rotation.
     * </pre></li>
     * </ul>
     */
    @Getter(AccessLevel.PRIVATE)
    private Set<NextKeyHashSource> nextKeyHashes;

    @Override
    protected DidMethodEnum getDidMethod() {
        return DidMethodEnum.WEBVH_1_0;
    }

    VcDataIntegrityCryptographicSuite getCryptoSuite() {
        if (this.verificationMethodKeyProvider != null) {
            return this.verificationMethodKeyProvider;
        }

        return this.cryptographicSuite;
    }

    /**
     * Updates a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log by taking into account other
     * features of this {@link WebVerifiableHistoryUpdater} object, optionally customized by previously calling fluent methods like
     * {@link WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder#verificationMethodKeyProvider}, {@link WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder#authenticationKeys(Map)} or
     * {@link WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder#assertionMethodKeys(Map)}.
     *
     * @param didLog to update. Expected to be resolvable/verifiable already.
     * @return a whole new <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log entry to be appended to the existing {@code didLog}
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason.
     * @see #updateDidLog(String, ZonedDateTime)
     */
    @Override
    public String updateDidLog(String didLog) throws DidLogUpdaterStrategyException {
        return updateDidLog(didLog, ZonedDateTime.now());
    }

    /**
     * The file-system-as-input variation of {@link #updateDidLog(String)}
     *
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason
     * @see #updateDidLog(String)
     */
    @Override
    public String updateDidLog(File didLogFile) throws DidLogUpdaterStrategyException {
        try {
            return updateDidLog(Files.readString(didLogFile.toPath()), ZonedDateTime.now());
        } catch (IOException e) {
            throw new DidLogUpdaterStrategyException(e);
        }
    }

    /**
     * Updates a <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <p>
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param resolvableDidLog to update. Expected to be resolvable/verifiable already.
     * @param zdt              a date-time with a time-zone in the ISO-8601 calendar system
     * @return a whole new  <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log entry to be appended to the existing {@code didLog}
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason.
     */
    @SuppressWarnings({"PMD.NcssCount", "PMD.CognitiveComplexity", "PMD.CyclomaticComplexity"})
    @Override
    public String updateDidLog(String resolvableDidLog, ZonedDateTime zdt) throws DidLogUpdaterStrategyException {

        try {
            super.peek(resolvableDidLog);
        } catch (DidLogMetaPeekerException e) {
            throw new DidLogUpdaterStrategyException(e);
        }

        // CAUTION Only activated DIDs can be updated
        if (super.didLogMeta.getParams().getDeactivated() != null && super.didLogMeta.getParams().getDeactivated()) {
            throw new DidLogUpdaterStrategyException("DID already deactivated");
        }

        if (!super.isVerificationMethodKeyProviderLegal(this.getCryptoSuite())) {
            throw new DidLogUpdaterStrategyException("Update key mismatch");
        }

        // While Key Pre-Rotation is active, all multikey formatted public keys added in a new 'updateKeys' list
        // MUST have their hashes listed in the 'nextKeyHashes' list from the previous log entry.
        if (super.didLogMeta.isKeyPreRotationActivated()) {
            boolean arePreRotatedUpdateKeys;
            try {
                arePreRotatedUpdateKeys = super.didLogMeta.arePreRotatedUpdateKeys(this.updateKeys);
            } catch (DidSidekicksException e) {
                throw new DidLogUpdaterStrategyException(e);
            }

            if (!arePreRotatedUpdateKeys) {
                throw new DidLogUpdaterStrategyException("Illegal updateKey detected");
            }

        } else if (this.updateKeys != null) {

            for (var key : this.updateKeys) {
                String multikey;
                try {
                    multikey = PemUtils.readEd25519PublicKeyPemFileToMultibase(key);
                } catch (DidSidekicksException e) {
                    throw new DidLogUpdaterStrategyException("Invalid verifying (public) ed25519 key supplied", e);
                }

                if (!this.getCryptoSuite().getVerificationKeyMultibase().equals(multikey)) {
                    throw new DidLogUpdaterStrategyException("No matching verifying (public) ed25519 key supplied");
                }
            }
        }

        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        //
        // The versionTime for each log entry MUST be greater than the previous entry’s time.
        // The versionTime of the last entry MUST be earlier than the current time.
        var lastEntryDateTime = ZonedDateTime.parse(super.didLogMeta.getDateTime());
        if (zdt.isBefore(lastEntryDateTime) || zdt.isEqual(lastEntryDateTime)) {
            throw new DidLogUpdaterStrategyException("The versionTime of the last entry MUST be earlier than the current time");
        }

        // Create initial did doc with placeholder
        var didDoc = new JsonObject();

        // take over context
        var context = new JsonArray();
        for (var ctx : super.didLogMeta.getDidDoc().getContext()) {
            context.add(ctx);
        }
        didDoc.add("@context", context);

        didDoc.addProperty("id", super.didLogMeta.getDidDoc().getId());
        // CAUTION "controller" property is omitted w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDSYS-352
        // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
        //didDoc.addProperty("controller", didTDW);

        if ((this.authenticationKeys == null || this.authenticationKeys.isEmpty())
                && (this.assertionMethodKeys == null || this.assertionMethodKeys.isEmpty())) {
            throw new DidLogUpdaterStrategyException("No update will take place as no verification material is supplied whatsoever");
        }

        var verificationMethod = new JsonArray();

        if (this.authenticationKeys != null && !this.authenticationKeys.isEmpty()) {

            JsonArray authentication = new JsonArray();
            for (var key : this.authenticationKeys.entrySet()) {

                authentication.add(super.didLogMeta.getDidDoc().getId() + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(super.didLogMeta.getDidDoc().getId(), key.getKey(), key.getValue()));
            }

            didDoc.add("authentication", authentication);
        }

        if (this.assertionMethodKeys != null && !this.assertionMethodKeys.isEmpty()) {

            JsonArray assertionMethod = new JsonArray();
            for (var key : this.assertionMethodKeys.entrySet()) {

                assertionMethod.add(super.didLogMeta.getDidDoc().getId() + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(super.didLogMeta.getDidDoc().getId(), key.getKey(), key.getValue()));
            }

            didDoc.add("assertionMethod", assertionMethod);
        }

        // NOTE that there is no need to add the rest of the existing (verification method) keys, as they can be
        //      added, if required, at any point again

        didDoc.add("verificationMethod", verificationMethod);

        /* https://identity.foundation/didwebvh/v1.0/#the-did-log-file:
        The DID log file contains a list of entries, one for each version of the DID
        A version of the DID is an update to the contents of the resolved DIDDoc for the DID, and/or a change to the
        parameters that control the generation and verification of the DID.
        Each entry is a JSON object consisting of the following properties.
        { "versionId": "", "versionTime": "", "parameters": {}, "state": {}, "proof" : [] }
         */

        // since did:tdw:0.4 ("Changes the DID log entry array to be named JSON objects or properties.")
        var didLogEntryWithoutProofAndSignature = new JsonObject();

        // https://identity.foundation/didwebvh/v1.0/#entry-hash-generation-and-verification:
        // For the first log entry, the predecessor versionId is the SCID (itself a hash),
        // while for all other entries it is the versionId item from the previous log entry.
        didLogEntryWithoutProofAndSignature.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, super.didLogMeta.getLastVersionId());

        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        //
        // The versionTime for each log entry MUST be greater than the previous entry’s time.
        // The versionTime of the last entry MUST be earlier than the current time.
        didLogEntryWithoutProofAndSignature.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME, DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));

        // The third item in the input JSON array MUST be the parameters JSON object.
        // The parameters are used to configure the DID generation and verification processes.
        // All parameters MUST be valid and all required values in the first version of the DID MUST be present.
        didLogEntryWithoutProofAndSignature.add(DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS, this.buildDidMethodParameters());

        // The JSON object "state" contains the DIDDoc for this version of the DID.
        didLogEntryWithoutProofAndSignature.add(DID_LOG_ENTRY_JSON_PROPERTY_STATE, didDoc);

        // See https://identity.foundation/didwebvh/v1.0/#generate-entry-hash
        // This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        // Once the process has run, the version number of this first version of the DID (1),
        // a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
        String entryHash;
        try (var hasher = JcsSha256Hasher.Companion.build()) {
            entryHash = hasher.base58btcEncodeMultihash(didLogEntryWithoutProofAndSignature.toString());
        } catch (DidSidekicksException e) {
            throw new DidLogUpdaterStrategyException(e);
        }

        // since did:tdw:0.4 ("Changes the DID log entry array to be named JSON objects or properties.")
        var didLogEntryWithoutProof = new JsonObject();

        var challenge = didLogMeta.getLastVersionNumber() + 1 + "-" + entryHash; // versionId as the proof challenge
        didLogEntryWithoutProof.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, challenge);
        didLogEntryWithoutProof.add(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME,
                didLogEntryWithoutProofAndSignature.get(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME));
        didLogEntryWithoutProof.add(DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS,
                didLogEntryWithoutProofAndSignature.get(DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS));
        didLogEntryWithoutProof.add(DID_LOG_ENTRY_JSON_PROPERTY_STATE,
                didLogEntryWithoutProofAndSignature.get(DID_LOG_ENTRY_JSON_PROPERTY_STATE));

        /*
        https://identity.foundation/didwebvh/v1.0/#update-rotate:
        6. Generate a Data Integrity proof on the DID log entry using an authorized key, as defined in the Authorized Keys
           section of this specification, and the proofPurpose set to assertionMethod.
        Since did.tdw:0.4 ->
           "Makes each DID version’s Data Integrity proof apply across the JSON DID log entry object, as is typical with Data Integrity proofs.
           Previously, the Data Integrity proof was generated across the current DIDDoc version, with the versionId as the challenge."
         */
        try {
            return this.getCryptoSuite().addProof(
                    didLogEntryWithoutProof.toString(), null, JCSHasher.PROOF_PURPOSE_ASSERTION_METHOD, zdt);
        } catch (VcDataIntegrityCryptographicSuiteException e) {
            throw new DidLogUpdaterStrategyException("Fail to build DID doc data integrity proof", e);
        }
    }

    /**
     * Simple type converter
     */
    private Set<String> loadUpdateKeys() throws DidLogUpdaterStrategyException {
        var keys = new HashSet<String>();
        for (var pemFile : this.updateKeys) {
            try {
                keys.add(PemUtils.readEd25519PublicKeyPemFileToMultibase(pemFile));
            } catch (DidSidekicksException ex) {
                throw new DidLogUpdaterStrategyException(ex);
            }
        }

        return keys;
    }

    /**
     * Simple type converter
     */
    private Set<String> loadNextUpdateKeys() throws DidLogUpdaterStrategyException {
        var keys = new HashSet<String>();
        for (var pemFile : this.nextUpdateKeys) {
            try {
                keys.add(NextKeyHashSource.of(pemFile).getHash());
            } catch (NextKeyHashSourceException ex) {
                throw new DidLogUpdaterStrategyException(ex);
            }
        }

        return keys;
    }

    /**
     * The <code>parameters</code> are used to configure the DID generation and verification processes.
     * All parameters MUST be valid and all required values in the first version of the DID MUST be present,
     * as <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">specified</a>:
     * <p>
     * A JSON array of strings that are hashes of multikey formatted public keys that MAY be added to the
     * list in the next log entry. At least one entry of <code>nextKeyHashes</code> MUST be added to the next <code>updateKeys</code> list.
     * <p>
     * <ul>
     * <li>The process for generating the hashes and additional details for using pre-rotation are defined
     *     in the Pre-Rotation Key Hash Generation and Verification section of this specification.</li>
     * <li>If not set in the first log entry, its value defaults to an empty array ([]).</li>
     * <li>If not set in other log entries, its value is retained from the most recent prior value.</li>
     * <li>Once the <code>nextKeyHashes</code> parameter has been set to a non-empty array, Key Pre-Rotation is active.
     *     While active, the properties <code>nextKeyHashes</code> and <code>updateKeys</code> MUST be present in all log entries.</li>
     * <li>While Key Pre-Rotation is active, all multikey formatted public keys added in a new <code>updateKeys</code> list
     *     MUST have their hashes listed in the <code>nextKeyHashes</code> list from the previous log entry.</li>
     * <li>A DID Controller MAY include extra hashes in the <code>nextKeyHashes</code> array that are not subsequently
     *     used in an <code>updateKeys</code> entry. Any unused hashes in <code>nextKeyHashes</code> arrays are ignored.</li>
     * <li>The value of <code>nextKeyHashes</code> MAY be set to an empty array (<code>[]</code>) to deactivate pre-rotation.</li>
     * </ul>
     *
     * @return a JSON object populated accordingly
     * @throws DidLogUpdaterStrategyException if any of files supplied via this class members
     *                                        (e.g. {@link #updateKeys} or {@link #nextUpdateKeys}) cannot be loaded
     *                                        or contain no valid public PEM keys
     */
    @SuppressWarnings({"PMD.CognitiveComplexity", "PMD.CyclomaticComplexity", "PMD.NPathComplexity"})
    private JsonObject buildDidMethodParameters() throws DidLogUpdaterStrategyException {

        var didMethodParameters = new JsonObject();

        var updateKeysJsonArray = new JsonArray();
        var nextKeyHashesJsonArray = new JsonArray();

        if ((this.updateKeys == null || this.updateKeys.isEmpty())
                && (this.nextUpdateKeys == null || this.nextUpdateKeys.isEmpty())
                && super.didLogMeta.isKeyPreRotationActivated()) {

            updateKeysJsonArray.add(this.getCryptoSuite().getVerificationKeyMultibase());

            didMethodParameters.add(NamedDidMethodParameters.NEXT_KEY_HASHES, new JsonArray()); // key pre-rotation MUST be deactivated

        } else if ((this.updateKeys == null || this.updateKeys.isEmpty())
                && (this.nextUpdateKeys == null || this.nextUpdateKeys.isEmpty())
                && !super.didLogMeta.isKeyPreRotationActivated()) {

            // all parameters remain the same

        } else if ((this.updateKeys == null || this.updateKeys.isEmpty())
                && (this.nextUpdateKeys != null && !this.nextUpdateKeys.isEmpty())
                && super.didLogMeta.isKeyPreRotationActivated()) {

            updateKeysJsonArray.add(this.getCryptoSuite().getVerificationKeyMultibase());

            loadNextUpdateKeys().forEach(nextKeyHashesJsonArray::add);
            didMethodParameters.add(NamedDidMethodParameters.NEXT_KEY_HASHES, nextKeyHashesJsonArray);

        } else if ((this.updateKeys == null || this.updateKeys.isEmpty())
                && (this.nextUpdateKeys != null && !this.nextUpdateKeys.isEmpty())
                && !super.didLogMeta.isKeyPreRotationActivated()) {

            loadNextUpdateKeys().forEach(nextKeyHashesJsonArray::add);
            didMethodParameters.add(NamedDidMethodParameters.NEXT_KEY_HASHES, nextKeyHashesJsonArray);

        } else if ((this.updateKeys != null && !this.updateKeys.isEmpty())
                && (this.nextUpdateKeys == null || this.nextUpdateKeys.isEmpty())
                && super.didLogMeta.isKeyPreRotationActivated()) {

            loadUpdateKeys().forEach(updateKeysJsonArray::add);
            if (!updateKeysJsonArray.contains(new JsonPrimitive(this.getCryptoSuite().getVerificationKeyMultibase()))) {
                updateKeysJsonArray.add(this.getCryptoSuite().getVerificationKeyMultibase());
            }

            didMethodParameters.add(NamedDidMethodParameters.NEXT_KEY_HASHES, new JsonArray()); // key pre-rotation MUST be deactivated

        } else if ((this.updateKeys != null && !this.updateKeys.isEmpty())
                && (this.nextUpdateKeys == null || this.nextUpdateKeys.isEmpty())
                && !super.didLogMeta.isKeyPreRotationActivated()) {

            // CAUTION No "updateKeys" can be set here. Otherwise, thrown is: "Invalid update key found. UpdateKey may only be set during key pre-rotation.".
            //         Hence, all parameters remain the same.

        } else if ((this.updateKeys != null && !this.updateKeys.isEmpty())
                && (this.nextUpdateKeys != null && !this.nextUpdateKeys.isEmpty())
                && super.didLogMeta.isKeyPreRotationActivated()) {

            updateKeysJsonArray.add(this.getCryptoSuite().getVerificationKeyMultibase());

            loadNextUpdateKeys().forEach(nextKeyHashesJsonArray::add);
            didMethodParameters.add(NamedDidMethodParameters.NEXT_KEY_HASHES, nextKeyHashesJsonArray);
        }
        /*} else {
            // all parameters remain the same
        }*/

        if (!updateKeysJsonArray.isEmpty()) {
            didMethodParameters.add(NamedDidMethodParameters.UPDATE_KEYS, updateKeysJsonArray);
        }

        if (!nextKeyHashesJsonArray.isEmpty()) {
            didMethodParameters.add(NamedDidMethodParameters.NEXT_KEY_HASHES, nextKeyHashesJsonArray);
        }

        return didMethodParameters;
    }
}