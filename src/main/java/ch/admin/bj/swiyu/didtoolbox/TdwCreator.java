package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategy;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.model.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.model.TdwDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;

/**
 * {@link TdwCreator} is a {@link DidLogCreatorStrategy} implementation in charge of
 * <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log generation.
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@link #builder()} method.
 * <p>
 * Once a {@link TdwCreator} object is "built", creating a <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a>
 * log goes simply by calling {@link #createDidLog(URL)} method. Optionally, but most likely, an already existing key material will
 * be also used in the process, so for the purpose there are further fluent methods available:
 * <ul>
 * <li>{@link TdwCreator.TdwCreatorBuilder#cryptographicSuite(VcDataIntegrityCryptographicSuite)} for the purpose of adding data integrity proof</li>
 * <li>{@link TdwCreator.TdwCreatorBuilder#authenticationKeys(Map)} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link TdwCreator.TdwCreatorBuilder#assertionMethodKeys(Map)} for setting/assertion
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
 * Instead, rather rely on the designated {@link DidLogCreatorContext} for the purpose. Needless to say,
 * the proper DID method must be supplied to the strategy - in this case it should be {@link DidMethodEnum#TDW_0_3}.
 * <p>
 */
@Builder
@Getter
public class TdwCreator extends AbstractDidLogEntryBuilder implements DidLogCreatorStrategy {

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
    @Deprecated
    private VcDataIntegrityCryptographicSuite verificationMethodKeyProvider;
    @Getter(AccessLevel.PRIVATE)
    private Set<File> updateKeys;
    @Getter(AccessLevel.PRIVATE)
    private boolean forceOverwrite;

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
     * @deprecated Use {@link #createDidLog(URL)} instead
     */
    @Deprecated
    public String create(URL identifierRegistryUrl) throws IOException {
        try {
            return createDidLog(identifierRegistryUrl, ZonedDateTime.now());
        } catch (DidLogCreatorStrategyException e) {
            throw new IOException(e);
        }
    }

    /**
     * Creates a valid <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log by taking into account other
     * features of this {@link TdwCreator} object, optionally customized by previously calling fluent methods like
     * {@link TdwCreator.TdwCreatorBuilder#verificationMethodKeyProvider}, {@link TdwCreator.TdwCreatorBuilder#authenticationKeys(Map)} or
     * {@link TdwCreator.TdwCreatorBuilder#assertionMethodKeys(Map)}.
     *
     * @param identifierRegistryUrl is the URL of a did.jsonl in its entirety w.r.t.
     *                              <a href="https://identity.foundation/didwebvh/v0.3/#the-did-to-https-transformation">the-did-to-https-transformation</a>
     * @return a valid <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log
     * @throws DidLogCreatorStrategyException if creation fails for whatever reason
     */
    @Override
    public String createDidLog(URL identifierRegistryUrl) throws DidLogCreatorStrategyException {
        return createDidLog(identifierRegistryUrl, ZonedDateTime.now());
    }

    /**
     * Left for the sake of backward compatibility. See deprecation notice.
     *
     * @deprecated Use {@link #createDidLog(URL, ZonedDateTime)} instead
     */
    @Deprecated
    public String create(URL identifierRegistryUrl, ZonedDateTime zdt) throws IOException {
        try {
            return createDidLog(identifierRegistryUrl, zdt);
        } catch (DidLogCreatorStrategyException e) {
            throw new IOException(e);
        }
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
     * @return valid DID log
     * @throws DidLogCreatorStrategyException if creation fails for whatever reason
     */
    @SuppressWarnings({"PMD.CyclomaticComplexity"})
    @Override
    public String createDidLog(URL identifierRegistryUrl, ZonedDateTime zdt) throws DidLogCreatorStrategyException {

        // Create initial did doc with placeholder
        var didDoc = createDidDoc(identifierRegistryUrl, this.authenticationKeys, this.assertionMethodKeys, this.forceOverwrite);

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

        // CAUTION nextKeyHashes parameter (pre-rotation keys) not (yet) implemented for the class
        didLogEntryWithoutProofAndSignature.add(createDidParams(this.getCryptoSuite(), this.updateKeys, null, null));

        // Add the initial DIDDoc
        // The fourth item in the input JSON array MUST be the JSON object {"value": <diddoc> }, where <diddoc> is the initial DIDDoc as described in the previous step 3.
        JsonObject initialDidDoc = new JsonObject();
        initialDidDoc.add("value", didDoc);
        didLogEntryWithoutProofAndSignature.add(initialDidDoc);

        // Generate SCID and replace placeholder in did doc
        String scid = buildSCID(didLogEntryWithoutProofAndSignature);

        /* https://identity.foundation/didwebvh/v0.3/#output-of-the-scid-generation-process:
        After the SCID is generated, the literal {SCID} placeholders are replaced by the generated SCID value (below).
        This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        Once the process has run, the version number of this first version of the DID (1),
        a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
         */

        didDoc = JsonParser.parseString(
                didDoc.toString().replace(SCID_PLACEHOLDER, scid)
        ).getAsJsonObject();

        var didLogEntryWithSCIDWithoutProofAndSignature = JsonParser.parseString(
                didLogEntryWithoutProofAndSignature.toString().replace(SCID_PLACEHOLDER, scid)
        ).getAsJsonArray();

        // See https://identity.foundation/didwebvh/v0.3/#generate-entry-hash
        // After the SCID is generated, the literal {SCID} placeholders are replaced by the generated SCID value (below).
        // This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        // Once the process has run, the version number of this first version of the DID (1),
        // a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
        String entryHash = buildSCID(didLogEntryWithSCIDWithoutProofAndSignature);

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
        try {
            proofs.add(JCSHasher.buildDataIntegrityProof(
                    didDoc, false, this.getCryptoSuite(), challenge, JCSHasher.PROOF_PURPOSE_AUTHENTICATION, zdt
            ));
        } catch (DidSidekicksException e) {
            throw new DidLogCreatorStrategyException(e);
        }
        didLogEntryWithProof.add(proofs);

        try {
            TdwDidLogMetaPeeker.peek(didLogEntryWithProof.toString()); // sanity check
        } catch (DidLogMetaPeekerException e) {
            throw new InvalidDidLogException("Creating a DID log resulted in unresolvable/unverifiable DID log", e);
        }

        return didLogEntryWithProof.toString();
    }
}