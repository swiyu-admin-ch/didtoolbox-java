package ch.admin.bj.swiyu.didtoolbox.webvh;

import ch.admin.bj.swiyu.didtoolbox.*;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.strategy.DidLogUpdaterContext;
import ch.admin.bj.swiyu.didtoolbox.strategy.DidLogUpdaterStrategy;
import ch.admin.bj.swiyu.didtoolbox.strategy.DidLogUpdaterStrategyException;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
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
 * <li>{@link WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} for setting the update (Ed25519) key</li>
 * <li>{@link WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder#authenticationKeys(Map)} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder#assertionMethodKeys(Map)} for setting/assertion
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
 * <p>
 * <p>
 * <strong>CAUTION</strong> Any explicit use of this class in your code is HIGHLY INADVISABLE.
 * Instead, rather rely on the designated {@link DidLogUpdaterContext} for the purpose. Needless to say,
 * the proper DID method must be supplied to the strategy - for that matter, simply use one of the available helpers like
 * {@link DidMethodEnum#detectDidMethod(String)} or {@link DidMethodEnum#detectDidMethod(File)}.
 * <p>
 */
@Builder
@Getter
public class WebVerifiableHistoryUpdater extends AbstractDidLogEntryBuilder implements DidLogUpdaterStrategy {

    private static final String SCID_PLACEHOLDER = "{SCID}";

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

    @Override
    protected DidMethodEnum getDidMethod() {
        return DidMethodEnum.WEBVH_1_0;
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
    @Override
    public String updateDidLog(String resolvableDidLog, ZonedDateTime zdt) throws DidLogUpdaterStrategyException {

        try {
            super.peek(resolvableDidLog);
        } catch (Exception e) { //} catch (DidResolveException | DidLogMetaPeekerException e) {
            throw new DidLogUpdaterStrategyException(e);
        }

        // CAUTION Only activated DIDs can be updated
        if (didLogMeta.getParams().getDeactivated() != null && didLogMeta.getParams().getDeactivated()) {
            throw new DidLogUpdaterStrategyException("DID already deactivated");
        }

        if (!this.verificationMethodKeyProvider.isKeyMultibaseInSet(didLogMeta.getParams().getUpdateKeys())) {
            throw new DidLogUpdaterStrategyException("Update key mismatch");
        }

        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        //
        // The versionTime for each log entry MUST be greater than the previous entry’s time.
        // The versionTime of the last entry MUST be earlier than the current time.
        var lastEntryDateTime = ZonedDateTime.parse(didLogMeta.getDateTime());
        if (zdt.isBefore(lastEntryDateTime) || zdt.isEqual(lastEntryDateTime)) {
            throw new DidLogUpdaterStrategyException("The versionTime of the last entry MUST be earlier than the current time");
        }

        // Create initial did doc with placeholder
        var didDoc = new JsonObject();

        // take over context
        var context = new JsonArray();
        for (var ctx : didLogMeta.getDidDoc().getContext()) {
            context.add(ctx);
        }
        didDoc.add("@context", context);

        didDoc.addProperty("id", this.didLogMeta.getDidDoc().getId());
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

                authentication.add(this.didLogMeta.getDidDoc().getId() + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(this.didLogMeta.getDidDoc().getId(), key.getKey(), key.getValue()));
            }

            didDoc.add("authentication", authentication);
        }

        if (this.assertionMethodKeys != null && !this.assertionMethodKeys.isEmpty()) {

            JsonArray assertionMethod = new JsonArray();
            for (var key : this.assertionMethodKeys.entrySet()) {

                assertionMethod.add(this.didLogMeta.getDidDoc().getId() + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(this.didLogMeta.getDidDoc().getId(), key.getKey(), key.getValue()));
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
        didLogEntryWithoutProofAndSignature.addProperty("versionId", didLogMeta.getLastVersionId());

        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        //
        // The versionTime for each log entry MUST be greater than the previous entry’s time.
        // The versionTime of the last entry MUST be earlier than the current time.
        didLogEntryWithoutProofAndSignature.addProperty("versionTime", DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));

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
                        throw new DidLogUpdaterStrategyException(e);
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

            didLogEntryWithoutProofAndSignature.add("parameters", didMethodParameters);

        } else {
            didLogEntryWithoutProofAndSignature.add("parameters", new JsonObject()); // CAUTION params remain the same
        }

        // The JSON object "state" contains the DIDDoc for this version of the DID.
        didLogEntryWithoutProofAndSignature.add("state", didDoc);

        // See https://identity.foundation/didwebvh/v1.0/#generate-entry-hash
        // This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        // Once the process has run, the version number of this first version of the DID (1),
        // a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
        String entryHash;
        try {
            entryHash = JCSHasher.buildSCID(didLogEntryWithoutProofAndSignature.toString());
        } catch (IOException e) {
            throw new DidLogUpdaterStrategyException(e);
        }

        // since did:tdw:0.4 ("Changes the DID log entry array to be named JSON objects or properties.")
        var didLogEntryWithProof = new JsonObject();

        var challenge = didLogMeta.getLastVersionNumber() + 1 + "-" + entryHash; // versionId as the proof challenge
        didLogEntryWithProof.addProperty("versionId", challenge);
        didLogEntryWithProof.add("versionTime", didLogEntryWithoutProofAndSignature.get("versionTime"));
        didLogEntryWithProof.add("parameters", didLogEntryWithoutProofAndSignature.get("parameters"));
        didLogEntryWithProof.add("state", didLogEntryWithoutProofAndSignature.get("state"));

        /*
        https://identity.foundation/didwebvh/v1.0/#update-rotate:
        6. Generate a Data Integrity proof on the DID log entry using an authorized key, as defined in the Authorized Keys
           section of this specification, and the proofPurpose set to assertionMethod.
        Since did.tdw:0.4 ->
           "Makes each DID version’s Data Integrity proof apply across the JSON DID log entry object, as is typical with Data Integrity proofs.
           Previously, the Data Integrity proof was generated across the current DIDDoc version, with the versionId as the challenge."
         */
        var proofs = new JsonArray();
        JsonObject proof;
        try {
            proof = JCSHasher.buildDataIntegrityProof(
                    didLogEntryWithProof, false, this.verificationMethodKeyProvider, null, JCSHasher.PROOF_PURPOSE_ASSERTION_METHOD, zdt);
        } catch (IOException e) {
            throw new DidLogUpdaterStrategyException("Fail to build DID doc data integrity proof", e);
        }
        // CAUTION Set proper "verificationMethod"
        proof.addProperty("verificationMethod", "did:key:" + this.verificationMethodKeyProvider.getVerificationKeyMultibase() + '#' + this.verificationMethodKeyProvider.getVerificationKeyMultibase());
        proofs.add(proof);
        didLogEntryWithProof.add("proof", proofs);

        var did = new Did(this.didLogMeta.getDidDoc().getId());
        try {
            // NOTE Enforcing DID log conformity is already part of the `resolve` method.
            // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
            did.resolveAll(new StringBuilder(resolvableDidLog.trim()).append(System.lineSeparator()).append(didLogEntryWithProof).toString()); // sanity check
        } catch (DidResolveException e) {
            throw new InvalidDidLogException("Updating the DID log resulted in unresolvable/unverifiable DID log", e);
        } finally {
            did.close();
        }

        return didLogEntryWithProof.toString();
    }
}