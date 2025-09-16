package ch.admin.bj.swiyu.didtoolbox.webvh;

import ch.admin.bj.swiyu.didtoolbox.*;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorStrategy;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorStrategyException;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import lombok.Builder;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.file.Files;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

/**
 * {@link WebVerifiableHistoryDeactivator} is a {@link DidLogDeactivatorStrategy} implementation in charge of
 * <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log deactivation (revoke).
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@link #builder()} method.
 * <p>
 * Once a {@link WebVerifiableHistoryDeactivator} object is "built", creating a <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>
 * log goes simply by calling {@link #deactivateDidLog(String)} method. Optionally, but most likely, an already existing key material will
 * be also used in the process, so for the purpose there are further fluent methods available:
 * <ul>
 * <li>{@link WebVerifiableHistoryDeactivator.WebVerifiableHistoryDeactivatorBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} for setting a signing (Ed25519) key</li>
 * </ul>
 * To load keys from the file system, the following helpers are available:
 * <ul>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(Reader, Reader)} for loading a signing (Ed25519) key from
 * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> files</li>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(InputStream, String, String, String)} for loading a signing (Ed25519) key from Java KeyStore (JKS) files</li>
 * <li>{@link JwkUtils#loadECPublicJWKasJSON(File, String)} for loading authentication/assertion public
 * EC P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a> keys from
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">PEM</a> files</li>
 * </ul>
 * <p>
 * <p>
 * <strong>CAUTION</strong> Any explicit use of this class in your code is HIGHLY INADVISABLE.
 * Instead, rather rely on the designated {@link DidLogCreatorContext.DidLogDeactivatorContext} for the purpose. Needless to say,
 * the proper DID method must be supplied to the strategy - for that matter, simply use one of the available helpers like
 * {@link DidMethodEnum#detectDidMethod(String)} or {@link DidMethodEnum#detectDidMethod(File)}.
 * <p>
 */
@Builder
public class WebVerifiableHistoryDeactivator extends AbstractDidLogEntryBuilder implements DidLogDeactivatorStrategy {

    @Builder.Default
    private VerificationMethodKeyProvider verificationMethodKeyProvider = new Ed25519VerificationMethodKeyProviderImpl();

    @Override
    protected DidMethodEnum getDidMethod() {
        return DidMethodEnum.WEBVH_1_0;
    }

    /**
     * Deactivates a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log by taking into account other
     * features of this {@link WebVerifiableHistoryDeactivator} object.
     *
     * @param didLog to deactivate. Expected to be resolvable/verifiable already.
     * @return a whole new <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log entry to be appended to the existing {@code didLog}
     * @throws DidLogDeactivatorStrategyException if deactivation fails for whatever reason.
     * @see #deactivateDidLog(String, ZonedDateTime)
     */
    @Override
    public String deactivateDidLog(String didLog) throws DidLogDeactivatorStrategyException {
        return deactivateDidLog(didLog, ZonedDateTime.now());
    }

    /**
     * The file-system-as-input variation of {@link #deactivateDidLog(String)}
     *
     * @throws DidLogDeactivatorStrategyException if deactivation fails for whatever reason
     * @see #deactivateDidLog(String)
     */
    @Override
    public String deactivateDidLog(File didLogFile) throws DidLogDeactivatorStrategyException {
        try {
            return deactivateDidLog(Files.readString(didLogFile.toPath()), ZonedDateTime.now());
        } catch (IOException e) {
            throw new DidLogDeactivatorStrategyException(e);
        }
    }

    /**
     * Deactivates a <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <p>
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param didLog to deactivate. Expected to be resolvable/verifiable already.
     * @param zdt    a date-time with a time-zone in the ISO-8601 calendar system
     * @return a whole new  <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log entry to be appended to the existing {@code didLog}
     * @throws DidLogDeactivatorStrategyException if deactivation fails for whatever reason.
     */
    @Override
    public String deactivateDidLog(String didLog, ZonedDateTime zdt) throws DidLogDeactivatorStrategyException {

        try {
            super.peek(didLog);
        } catch (Exception e) { //} catch (DidResolveException | DidLogMetaPeekerException e) {
            throw new DidLogDeactivatorStrategyException(e);
        }

        // CAUTION Only activated DIDs can be updated
        if (didLogMeta.getParams().getDeactivated() != null && didLogMeta.getParams().getDeactivated()) {
            throw new DidLogDeactivatorStrategyException("DID already deactivated");
        }

        if (!this.verificationMethodKeyProvider.isKeyMultibaseInSet(didLogMeta.getParams().getUpdateKeys())) {
            throw new DidLogDeactivatorStrategyException("Deactivation key mismatch");
        }

        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        //
        // The versionTime for each log entry MUST be greater than the previous entry’s time.
        // The versionTime of the last entry MUST be earlier than the current time.
        var lastEntryDateTime = ZonedDateTime.parse(didLogMeta.getDateTime());
        if (zdt.isBefore(lastEntryDateTime) || zdt.isEqual(lastEntryDateTime)) {
            throw new DidLogDeactivatorStrategyException("The versionTime of the last entry MUST be earlier than the current time");
        }

        // Create initial did doc with placeholder
        var didDoc = new JsonObject();

        // take over context
        var context = new JsonArray();
        for (var ctx : didLogMeta.getDidDoc().getContext()) {
            context.add(ctx);
        }
        didDoc.add("@context", context);

        didDoc.addProperty("id", didLogMeta.getDidDoc().getId());
        // CAUTION "controller" property is omitted w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDSYS-352
        // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
        //didDoc.addProperty("controller", didTDW);

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
        // Define the parameters (https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters)

        var didMethodParameters = new JsonObject();
        didMethodParameters.addProperty("deactivated", true);
        // https://identity.foundation/didwebvh/v1.0/#deactivate-revoke:
        // A DID MAY update the DIDDoc further to indicate the deactivation of the DID, such as including an empty updateKeys list
        // ("updateKeys": []) in the parameters, preventing further versions of the DID.
        didMethodParameters.add("updateKeys", new JsonArray());

        didLogEntryWithoutProofAndSignature.add("parameters", didMethodParameters);

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
            throw new DidLogDeactivatorStrategyException(e);
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
            throw new DidLogDeactivatorStrategyException("Fail to build DID doc data integrity proof", e);
        }
        // CAUTION Set proper "verificationMethod"
        proof.addProperty("verificationMethod", "did:key:" + this.verificationMethodKeyProvider.getVerificationKeyMultibase() + '#' + this.verificationMethodKeyProvider.getVerificationKeyMultibase());
        proofs.add(proof);
        didLogEntryWithProof.add("proof", proofs);

        Did did = new Did(didLogMeta.getDidDoc().getId());
        try {
            // NOTE Enforcing DID log conformity is already part of the `resolve` method.
            // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
            did.resolveAll(new StringBuilder(didLog.trim()).append(System.lineSeparator()).append(didLogEntryWithProof).toString()); // sanity check
        } catch (DidResolveException e) {
            throw new InvalidDidLogException("Deactivating the DID log resulted in unresolvable/unverifiable DID log", e);
        } finally {
            did.close();
        }

        return didLogEntryWithProof.toString();
    }
}