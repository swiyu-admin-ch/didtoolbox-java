package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.*;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
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
import java.nio.file.Files;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * {@link TdwUpdater} is a {@link DidLogUpdaterStrategy} implementation in charge of
 * <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log update (rotate).
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@code builder()} method.
 * <p>
 * Once a {@link TdwUpdater} object is properly "built"
 * (i.e. with some proper cryptographic suite and verification material included),
 * creating a <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a>
 * log goes simply by calling {@link #updateDidLog(String)} method.
 * So, before calling the {@code build()} method there are also these fluent methods (setters) available:
 * <ul>
 * <li>{@link TdwUpdater#cryptographicSuite} for the purpose of adding data integrity proof</li>
 * <li>{@link TdwUpdater#authenticationKeys} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link TdwUpdater#assertionMethodKeys} for setting/assertion
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * </ul>
 * To load required (Ed25519) keys (e.g. from the file system in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format),
 * feel free to explore all available {@link VerificationMethodKeyProvider} implementations.
 * <p>
 * To load authentication/assertion public EC P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a> keys from
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">PEM</a> files, you may rely on {@link JwkUtils}.
 * <p>
 * <strong>CAUTION</strong> Any explicit use of this class in your code is HIGHLY INADVISABLE.
 * Instead, rather rely on the designated {@link DidLogUpdaterContext} for the purpose. Needless to say,
 * the proper DID method must be supplied to the strategy - for that matter, simply use one of the available helpers like
 * {@link DidMethodEnum#detectDidMethod(String)} or {@link DidMethodEnum#detectDidMethod(File)}.
 */
@SuppressWarnings({"PMD.GodClass"})
@Builder
@Getter
public class TdwUpdater extends AbstractDidLogEntryBuilder implements DidLogUpdaterStrategy {

    private static final String SCID_PLACEHOLDER = "{SCID}";

    /**
     * Yet another <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent method</a> of the class.
     * Introduced for the purpose of supplying <a href="https://www.w3.org/TR/did-1.0/#verification-material">verification material</a>
     * for DID document.
     * More specifically, the focus here is on <a href="https://www.w3.org/TR/did-1.0/#assertion">assertion</a>
     * verification relationships.
     * <p>
     * The supplied {@link Map} object should contain multiple <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Keys (JWKs)</a>, whereas:
     * <p>
     * 1. The (map) key is a string representing both a {@code kid} (of a <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Key (JWK)</a>)
     * as well as a <a href="https://www.w3.org/TR/did-1.0/#fragment">fragment identifier</a> for the verification relationship.
     * <p>
     * 2. The (map) value is a string representation of a <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Key (JWK)</a>
     * containing no private members, thus usable as value of the {@code publicKeyJwk} property of {@code verificationMethod}.
     */
    @Getter(AccessLevel.PRIVATE)
    private Map<String, String> assertionMethodKeys;

    /**
     * Yet another <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent method</a> of the class.
     * Introduced for the purpose of supplying <a href="https://www.w3.org/TR/did-1.0/#verification-material">verification material</a>
     * for DID document.
     * More specifically, the focus here is on <a href="https://www.w3.org/TR/did-1.0/#authentication">authentication</a>
     * verification relationships.
     * <p>
     * The supplied {@link Map} object should contain multiple <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Keys (JWKs)</a>, whereas:
     * <p>
     * 1. The (map) key is a string representing both a {@code kid} (of a <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Key (JWK)</a>)
     * as well as a <a href="https://www.w3.org/TR/did-1.0/#fragment">fragment identifier</a> for the verification relationship.
     * <p>
     * 2. The (map) value is a string representation of a <a href="https://www.rfc-editor.org/rfc/rfc7517">JSON Web Key (JWK)</a>
     * containing no private members, thus usable as value of the {@code publicKeyJwk} property of {@code verificationMethod}.
     */
    @Getter(AccessLevel.PRIVATE)
    private Map<String, String> authenticationKeys;

    /**
     * Replaces the depr. {@link #verificationMethodKeyProvider},
     * but gets no precedence over it (if both called against the same object).
     *
     * @since 1.8.0
     */
    @Builder.Default
    @Getter(AccessLevel.PRIVATE)
    private VcDataIntegrityCryptographicSuite cryptographicSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();

    /**
     * @deprecated Use {@link #cryptographicSuite} instead
     */
    @Getter(AccessLevel.PRIVATE)
    @Deprecated(since = "1.8.0")
    private VcDataIntegrityCryptographicSuite verificationMethodKeyProvider;

    /**
     * Holder of the <a href="https://identity.foundation/didwebvh/v0.3/#didwebvh-did-method-parameters">updateKeys</a>
     * DID method parameter:
     * <pre>
     * A JSON array of multikey formatted public keys associated with the private keys that are authorized to sign the log entries that update the DID.
     * </pre>
     * <p>
     * This is an alternative and more potent method to supply the parameter.
     * Eventually, all the keys supplied one way or another are simply combined into a distinct list of values.
     * <p>
     * HINT: Use available {@link UpdateKeysDidMethodParameter} static factory methods to supply public keys.
     *
     * @since 1.8.0
     */
    @Getter(AccessLevel.PRIVATE)
    private Set<UpdateKeysDidMethodParameter> updateKeysDidMethodParameter;

    /**
     * Holder of the <a href="https://identity.foundation/didwebvh/v0.3/#didwebvh-did-method-parameters">updateKeys</a>
     * DID method parameter:
     * <pre>
     * A JSON array of multikey formatted public keys associated with the private keys that are authorized to sign the log entries that update the DID.
     * </pre>
     *
     * @deprecated Use the {@link #updateKeysDidMethodParameter} method instead
     */
    @Deprecated(since = "1.8.0")
    public void updateKeys(Set<File> pemFiles) throws UpdateKeysDidMethodParameterException {
        updateKeysDidMethodParameter.addAll(UpdateKeysDidMethodParameter.of(pemFiles));
    }

    private VcDataIntegrityCryptographicSuite getCryptoSuite() {
        if (this.verificationMethodKeyProvider != null) {
            return this.verificationMethodKeyProvider;
        }

        return this.cryptographicSuite;
    }

    @Override
    protected DidMethodEnum getDidMethod() {
        return DidMethodEnum.TDW_0_3;
    }

    /**
     * Left for the sake of backward compatibility. See deprecation notice.
     *
     * @deprecated Use {@link #updateDidLog(String)} instead
     */
    @Deprecated
    public String update(String didLog) throws TdwUpdaterException {
        try {
            return updateDidLog(didLog, ZonedDateTime.now());
        } catch (DidLogUpdaterStrategyException e) {
            throw new TdwUpdaterException(e);
        }
    }

    /**
     * Updates a valid <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log by taking into account other
     * features of this {@link TdwUpdater} object, optionally customized by previously calling fluent methods like
     * {@link TdwUpdater#verificationMethodKeyProvider}, {@link TdwUpdater#authenticationKeys} or
     * {@link TdwUpdater#assertionMethodKeys}.
     *
     * @param didLog to update. Expected to be resolvable/verifiable already.
     * @return a whole new <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log entry to be appended to the existing {@code didLog}
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason.
     * @throws IncompleteDidLogEntryBuilderException if either no cryptographic suite or no proper verification material has been supplied yet
     * @see #update(String, ZonedDateTime)
     */
    @Override
    public String updateDidLog(String didLog) throws DidLogUpdaterStrategyException {
        return updateDidLog(didLog, ZonedDateTime.now());
    }

    /**
     * Left for the sake of backward compatibility. See deprecation notice.
     *
     * @deprecated Use {@link #updateDidLog(File)} instead
     */
    @Deprecated
    String update(File didLogFile) throws TdwUpdaterException, IOException {
        try {
            return updateDidLog(Files.readString(didLogFile.toPath()), ZonedDateTime.now());
        } catch (DidLogUpdaterStrategyException e) {
            throw new TdwUpdaterException(e);
        }
    }

    /**
     * The file-system-as-input variation of {@link #updateDidLog(String)}
     *
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason
     * @throws IncompleteDidLogEntryBuilderException if either no cryptographic suite or no proper verification material has been supplied yet
     * @see #updateDidLog(String, ZonedDateTime)
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
     * Left for the sake of backward compatibility. See deprecation notice.
     *
     * @deprecated Use {@link #updateDidLog(File)} instead
     */
    @Deprecated
    String update(String resolvableDidLog, ZonedDateTime zdt) throws TdwUpdaterException {
        try {
            return updateDidLog(resolvableDidLog, zdt);
        } catch (DidLogUpdaterStrategyException e) {
            throw new TdwUpdaterException(e);
        }
    }

    /**
     * Updates a <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <p>
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param resolvableDidLog to update. Expected to be resolvable/verifiable already.
     * @param zdt              a date-time with a time-zone in the ISO-8601 calendar system
     * @return a whole new  <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log entry to be appended to the existing {@code didLog}
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason.
     * @throws IncompleteDidLogEntryBuilderException if either no cryptographic suite or no proper verification material has been supplied yet
     */
    @SuppressWarnings({"PMD.NcssCount", "PMD.CognitiveComplexity", "PMD.CyclomaticComplexity"})
    @Override
    public String updateDidLog(String resolvableDidLog, ZonedDateTime zdt) throws DidLogUpdaterStrategyException {

        if (getCryptoSuite() == null) {
            throw new IncompleteDidLogEntryBuilderException("No cryptographic suite supplied");
        }

        try {
            super.peek(resolvableDidLog);
        } catch (DidLogMetaPeekerException e) {
            throw new DidLogUpdaterStrategyException(e);
        }

        // CAUTION Only activated DIDs can be updated
        if (this.didLogMeta.getParams().getDeactivated() != null && this.didLogMeta.getParams().getDeactivated()) {
            throw new DidLogUpdaterStrategyException("DID already deactivated");
        }

        if (!this.getCryptoSuite().isKeyMultibaseInSet(this.didLogMeta.getParams().getUpdateKeys())) {
            throw new DidLogUpdaterStrategyException("Update key mismatch");
        }

        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        //
        // The versionTime for each log entry MUST be greater than the previous entry’s time.
        // The versionTime of the last entry MUST be earlier than the current time.
        var lastEntryDateTime = ZonedDateTime.parse(this.didLogMeta.getDateTime());
        if (zdt.isBefore(lastEntryDateTime) || zdt.isEqual(lastEntryDateTime)) {
            throw new DidLogUpdaterStrategyException("The versionTime of the last entry MUST be earlier than the current time");
        }

        // Create initial did doc with placeholder
        var didDoc = new JsonObject();

        // take over context
        var context = new JsonArray();
        for (var ctx : this.didLogMeta.getDidDoc().getContext()) {
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
            throw new IncompleteDidLogEntryBuilderException("No verification material is supplied");
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

        // The DID log entry is an input JSON array that when completed contains the following items:
        // [ versionId, versionTime, parameters, DIDDoc State, Data Integrity Proof ].

        var didLogEntryWithoutProofAndSignature = new JsonArray();

        // https://identity.foundation/didwebvh/v0.3/#entry-hash-generation-and-verification:
        // For the first log entry, the predecessor versionId is the SCID (itself a hash),
        // while for all other entries it is the versionId item from the previous log entry.
        didLogEntryWithoutProofAndSignature.add(this.didLogMeta.getLastVersionId());

        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        //
        // The versionTime for each log entry MUST be greater than the previous entry’s time.
        // The versionTime of the last entry MUST be earlier than the current time.
        didLogEntryWithoutProofAndSignature.add(DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));

        // The third item in the input JSON array MUST be the parameters JSON object.
        // The parameters are used to configure the DID generation and verification processes.
        // All parameters MUST be valid and all required values in the first version of the DID MUST be present.
        if (this.updateKeysDidMethodParameter != null) {
            didLogEntryWithoutProofAndSignature.add(buildDidMethodParameters());
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
        String scid;
        try {
            scid = buildSCID(didLogEntryWithoutProofAndSignature);
        } catch (DidLogCreatorStrategyException e) {
            throw new DidLogUpdaterStrategyException(e);
        }

        JsonArray didLogEntryWithProof = new JsonArray();
        var challenge = this.didLogMeta.getLastVersionNumber() + 1 + "-" + scid; // versionId as the proof challenge
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
            proof = JCSHasher.buildDataIntegrityProof(
                    didDoc, false, this.getCryptoSuite(), challenge, "authentication", zdt);
        } catch (DidSidekicksException e) {
            throw new DidLogUpdaterStrategyException("Fail to build DID doc data integrity proof", e);
        }
        // CAUTION Set proper "verificationMethod"
        proof.addProperty("verificationMethod", "did:key:" + this.getCryptoSuite().getVerificationKeyMultibase() + '#' + this.getCryptoSuite().getVerificationKeyMultibase());
        proofs.add(proof);
        didLogEntryWithProof.add(proofs);

        try (var did = new Did(this.didLogMeta.getDidDoc().getId())) {
            // NOTE Enforcing DID log conformity by calling:
            //      ch.admin.eid.didtoolbox.DidLogEntryValidator.Companion
            //          .from(DidLogEntryJsonSchema.V03_EID_CONFORM)
            //          .validate(didLogEntryWithProof.toString());
            //      would not be necessary here, as it is already part of the `resolve` method.
            // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
            did.resolveAll(new StringBuilder(resolvableDidLog.trim()).append(System.lineSeparator()).append(didLogEntryWithProof).toString()); // sanity check
        } catch (DidResolveException e) {
            throw new InvalidDidLogException("Updating the DID log resulted in unresolvable/unverifiable DID log", e);
        }

        return didLogEntryWithProof.toString();
    }

    @SuppressWarnings({"PMD.AvoidInstantiatingObjectsInLoops", "PMD.EmptyCatchBlock"})
    private JsonObject buildDidMethodParameters() throws DidLogUpdaterStrategyException {

        var updateKeysJsonArray = new JsonArray();

        Set<String> newUpdateKeys = new HashSet<>();
        if (this.updateKeysDidMethodParameter != null) {
            newUpdateKeys.addAll(
                    Set.of(this.updateKeysDidMethodParameter.stream().map(UpdateKeysDidMethodParameter::getUpdateKey).toArray(String[]::new))
            );
        }

        if (!super.didLogMeta.getParams().getUpdateKeys().containsAll(newUpdateKeys)
                && this.updateKeysDidMethodParameter != null) { // need for change?

            for (var param : this.updateKeysDidMethodParameter) {

                var updateKey = param.getUpdateKey();

                // it is a distinct list of keys, after all
                if (!updateKeysJsonArray.contains(new JsonPrimitive(updateKey))) {
                    updateKeysJsonArray.add(updateKey);
                }
            }
        }

        var didMethodParameters = new JsonObject();
        if (!updateKeysJsonArray.isEmpty()) {
            didMethodParameters.add(NamedDidMethodParameters.UPDATE_KEYS, updateKeysJsonArray);
        }

        return didMethodParameters;
    }
}