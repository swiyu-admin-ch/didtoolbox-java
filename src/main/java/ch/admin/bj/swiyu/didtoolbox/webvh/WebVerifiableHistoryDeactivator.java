package ch.admin.bj.swiyu.didtoolbox.webvh;

import ch.admin.bj.swiyu.didtoolbox.*;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorStrategy;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.model.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.model.NamedDidMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.io.File;
import java.io.IOException;
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
 * <li>{@link WebVerifiableHistoryDeactivator.WebVerifiableHistoryDeactivatorBuilder#cryptographicSuite(VcDataIntegrityCryptographicSuite)} for the purpose of adding data integrity proof</li>
 * </ul>
 * To load required (Ed25519) keys (e.g. from the file system in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format),
 * feel free to explore all available {@link VerificationMethodKeyProvider} implementations.
 * <p>
 * To load authentication/assertion public EC P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a> keys from
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">PEM</a> files, you may rely on {@link JwkUtils}.
 * <p>
 * <p>
 * <strong>CAUTION</strong> Any explicit use of this class in your code is HIGHLY INADVISABLE.
 * Instead, rather rely on the designated {@link DidLogDeactivatorContext} for the purpose. Needless to say,
 * the proper DID method must be supplied to the strategy - for that matter, simply use one of the available helpers like
 * {@link DidMethodEnum#detectDidMethod(String)} or {@link DidMethodEnum#detectDidMethod(File)}.
 * <p>
 */
@Builder
public class WebVerifiableHistoryDeactivator extends AbstractDidLogEntryBuilder implements DidLogDeactivatorStrategy {

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

    @Override
    protected DidMethodEnum getDidMethod() {
        return DidMethodEnum.WEBVH_1_0;
    }

    private VcDataIntegrityCryptographicSuite getCryptoSuite() {
        if (this.verificationMethodKeyProvider != null) {
            return this.verificationMethodKeyProvider;
        }

        return this.cryptographicSuite;
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
    @SuppressWarnings({"PMD.CyclomaticComplexity"})
    @Override
    public String deactivateDidLog(String didLog, ZonedDateTime zdt) throws DidLogDeactivatorStrategyException {

        try {
            super.peek(didLog);
        } catch (DidLogMetaPeekerException e) {
            throw new DidLogDeactivatorStrategyException(e);
        }

        // CAUTION Only activated DIDs can be updated
        if (didLogMeta.getParams().getDeactivated() != null && didLogMeta.getParams().getDeactivated()) {
            throw new DidLogDeactivatorStrategyException("DID already deactivated");
        }

        if (!this.getCryptoSuite().isKeyMultibaseInSet(didLogMeta.getParams().getUpdateKeys())) {
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
        didLogEntryWithoutProofAndSignature.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, didLogMeta.getLastVersionId());

        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        //
        // The versionTime for each log entry MUST be greater than the previous entry’s time.
        // The versionTime of the last entry MUST be earlier than the current time.
        didLogEntryWithoutProofAndSignature.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME, DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));

        // The third item in the input JSON array MUST be the parameters JSON object.
        // The parameters are used to configure the DID generation and verification processes.
        // All parameters MUST be valid and all required values in the first version of the DID MUST be present.
        // Define the parameters (https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters)

        var didMethodParameters = new JsonObject();
        didMethodParameters.addProperty("deactivated", true);
        // https://identity.foundation/didwebvh/v1.0/#deactivate-revoke:
        // A DID MAY update the DIDDoc further to indicate the deactivation of the DID, such as including an empty updateKeys list
        // ("updateKeys": []) in the parameters, preventing further versions of the DID.
        didMethodParameters.add(NamedDidMethodParameters.UPDATE_KEYS, new JsonArray());

        didLogEntryWithoutProofAndSignature.add(DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS, didMethodParameters);

        // The JSON object "state" contains the DIDDoc for this version of the DID.
        didLogEntryWithoutProofAndSignature.add(DID_LOG_ENTRY_JSON_PROPERTY_STATE, didDoc);

        // See https://identity.foundation/didwebvh/v1.0/#generate-entry-hash
        // This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        // Once the process has run, the version number of this first version of the DID (1),
        // a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
        String scid;
        try {
            scid = buildSCID(didLogEntryWithoutProofAndSignature);
        } catch (DidLogCreatorStrategyException e) {
            throw new DidLogDeactivatorStrategyException(e);
        }

        // since did:tdw:0.4 ("Changes the DID log entry array to be named JSON objects or properties.")
        var didLogEntryWithoutProof = new JsonObject();

        var challenge = didLogMeta.getLastVersionNumber() + 1 + "-" + scid; // versionId as the proof challenge
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
        try (var did = new Did(super.didLogMeta.getDidDoc().getId())) {
            var didLogEntry = this.getCryptoSuite().addProof(
                    didLogEntryWithoutProof.toString(), null, JCSHasher.PROOF_PURPOSE_ASSERTION_METHOD, zdt);

            did.resolveAll(new StringBuilder(didLog.trim()).append(System.lineSeparator()).append(didLogEntry).toString()); // sanity check

            return didLogEntry;
        } catch (VcDataIntegrityCryptographicSuiteException exc) {
            throw new DidLogDeactivatorStrategyException(exc);
        } catch (DidResolveException exc) {
            throw new InvalidDidLogException("Deactivating the DID log resulted in unresolvable/unverifiable DID log", exc);
        }
    }
}