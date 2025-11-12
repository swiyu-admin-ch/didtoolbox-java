package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorStrategy;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogDeactivatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.model.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.model.NamedDidMethodParameters;
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
 * {@link TdwDeactivator} is a {@link DidLogDeactivatorStrategy} implementation in charge of
 * <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log deactivation (revoke).
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@link #builder()} method.
 * <p>
 * Once a {@link TdwDeactivator} object is "built", creating a <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a>
 * log goes simply by calling {@link #deactivateDidLog(String)} method. Optionally, but most likely, an already existing key material will
 * be also used in the process, so for the purpose there are further fluent methods available:
 * <ul>
 * <li>{@link TdwDeactivator.TdwDeactivatorBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} for setting a signing (Ed25519) key</li>
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
 * Instead, rather rely on the designated {@link DidLogDeactivatorContext} for the purpose. Needless to say,
 * the proper DID method must be supplied to the strategy - for that matter, simply use one of the available helpers like
 * {@link DidMethodEnum#detectDidMethod(String)} or {@link DidMethodEnum#detectDidMethod(File)}.
 * <p>
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
@Builder
public class TdwDeactivator extends AbstractDidLogEntryBuilder implements DidLogDeactivatorStrategy {

    @Builder.Default
    private VerificationMethodKeyProvider verificationMethodKeyProvider = new Ed25519VerificationMethodKeyProviderImpl();

    @Override
    protected DidMethodEnum getDidMethod() {
        return DidMethodEnum.TDW_0_3;
    }

    /**
     * Left for the sake of backward compatibility. See deprecation notice.
     *
     * @deprecated Use {@link #deactivateDidLog(String)} instead
     */
    @Deprecated
    public String deactivate(String didLog) throws TdwDeactivatorException {
        try {
            return deactivateDidLog(didLog, ZonedDateTime.now());
        } catch (DidLogDeactivatorStrategyException e) {
            throw new TdwDeactivatorException(e);
        }
    }

    /**
     * Deactivates a valid <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log by taking into account other
     * features of this {@link TdwDeactivator} object.
     *
     * @param didLog to deactivate. Expected to be resolvable/verifiable already.
     * @return a whole new <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log entry to be appended to the existing {@code didLog}
     * @throws DidLogDeactivatorStrategyException if deactivation fails for whatever reason.
     * @see #deactivateDidLog(String, ZonedDateTime)
     */
    @Override
    public String deactivateDidLog(String didLog) throws DidLogDeactivatorStrategyException {
        return deactivateDidLog(didLog, ZonedDateTime.now());
    }

    /**
     * Left for the sake of backward compatibility. See deprecation notice.
     *
     * @deprecated Use {@link #deactivateDidLog(File)} instead
     */
    @Deprecated
    String deactivate(File didLogFile) throws TdwDeactivatorException, IOException {
        try {
            return deactivateDidLog(Files.readString(didLogFile.toPath()), ZonedDateTime.now());
        } catch (DidLogDeactivatorStrategyException e) {
            throw new TdwDeactivatorException(e);
        }
    }

    /**
     * The file-system-as-input variation of {@link #deactivateDidLog(String)}
     *
     * @throws DidLogDeactivatorStrategyException if deactivation fails for whatever reason
     * @see #deactivateDidLog(String, ZonedDateTime)
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
     * Left for the sake of backward compatibility. See deprecation notice.
     *
     * @deprecated Use {@link #deactivateDidLog(String, ZonedDateTime)} instead
     */
    @Deprecated
    public String deactivate(String didLog, ZonedDateTime zdt) throws TdwDeactivatorException {
        try {
            return deactivateDidLog(didLog, zdt);
        } catch (DidLogDeactivatorStrategyException e) {
            throw new TdwDeactivatorException(e);
        }
    }

    /**
     * Deactivates a <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <p>
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param didLog to deactivate. Expected to be resolvable/verifiable already.
     * @param zdt    a date-time with a time-zone in the ISO-8601 calendar system
     * @return a whole new <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log entry to be appended to the existing {@code didLog}
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
        // Define the parameters (https://identity.foundation/didwebvh/v0.3/#didtdw-did-method-parameters)

        var didMethodParameters = new JsonObject();
        didMethodParameters.addProperty("deactivated", true);
        // https://identity.foundation/didwebvh/v0.3/#deactivate-revoke:
        // A DID MAY update the DIDDoc further to indicate the deactivation of the DID, such as including an empty updateKeys list
        // ("updateKeys": []) in the parameters, preventing further versions of the DID.
        didMethodParameters.add(NamedDidMethodParameters.UPDATE_KEYS, new JsonArray());

        didLogEntryWithoutProofAndSignature.add(didMethodParameters);

        // The fourth item in the input JSON array MUST be the JSON object {"value": <diddoc> }, where <diddoc> is the initial DIDDoc as described in the previous step 3.
        var didDocJson = new JsonObject();
        didDocJson.add("value", didDoc);
        didLogEntryWithoutProofAndSignature.add(didDocJson);

        // See https://identity.foundation/didwebvh/v0.3/#generate-entry-hash
        // This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        // Once the process has run, the version number of this first version of the DID (1),
        // a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
        String entryHash;
        try {
            entryHash = JCSHasher.buildSCID(didLogEntryWithoutProofAndSignature);
        } catch (IOException e) {
            throw new DidLogDeactivatorStrategyException(e);
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
        JsonObject proof;
        try {
            proof = JCSHasher.buildDataIntegrityProof(didDoc, false, this.verificationMethodKeyProvider, challenge, "authentication", zdt);
        } catch (IOException e) {
            throw new DidLogDeactivatorStrategyException("Fail to build DID doc data integrity proof", e);
        }
        // CAUTION Set proper "verificationMethod"
        proof.addProperty("verificationMethod", "did:key:" + this.verificationMethodKeyProvider.getVerificationKeyMultibase() + '#' + this.verificationMethodKeyProvider.getVerificationKeyMultibase());
        proofs.add(proof);
        didLogEntryWithProof.add(proofs);

        Did did = new Did(didLogMeta.getDidDoc().getId());
        try {
            // NOTE Enforcing DID log conformity by calling:
            //      ch.admin.eid.didtoolbox.DidLogEntryValidator.Companion
            //          .from(DidLogEntryJsonSchema.V03_EID_CONFORM)
            //          .validate(didLogEntryWithProof.toString());
            //      would not be necessary here, as it is already part of the `resolve` method.
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