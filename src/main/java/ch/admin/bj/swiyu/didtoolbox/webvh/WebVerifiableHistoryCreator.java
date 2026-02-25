package ch.admin.bj.swiyu.didtoolbox.webvh;

import ch.admin.bj.swiyu.didtoolbox.AbstractDidLogEntryBuilder;
import ch.admin.bj.swiyu.didtoolbox.JCSHasher;
import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.VerificationMethodKeyProvider;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategy;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.IncompleteDidLogEntryBuilderException;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.eid.did_sidekicks.DidDoc;
import ch.admin.eid.did_sidekicks.VerificationMethod;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.io.File;
import java.net.URL;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * {@link WebVerifiableHistoryCreator} is a {@link DidLogCreatorStrategy} implementation in charge of
 * <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log generation.
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@code builder()} method.
 * <p>
 * Once a {@link WebVerifiableHistoryCreator} object is properly "built"
 * (i.e. with some proper cryptographic suite and verification material included),
 * creating a <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>
 * log goes simply by calling {@link #createDidLog(URL)} method.
 * So, before calling the {@code build()} method there are also these fluent methods available:
 * <ul>
 * <li>{@link WebVerifiableHistoryCreator#verificationMethodKeyProvider} for the purpose of adding data integrity proof</li>
 * <li>{@link WebVerifiableHistoryCreator#authentications} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link WebVerifiableHistoryCreator#assertionMethods} for setting/assertion
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * </ul>
 * To load required (Ed25519) keys (e.g. from the file system in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format),
 * feel free to explore all available {@link VerificationMethodKeyProvider} implementations.
 * <p>
 * To load authentication/assertion public EC P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a> keys from
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">PEM</a> files, you may rely on {@link JwkUtils}.
 * <p>
 * <strong>CAUTION</strong> Any explicit use of this class in your code is HIGHLY INADVISABLE.
 * Instead, rather rely on the designated {@link DidLogCreatorContext} for the purpose. Needless to say,
 * the proper DID method must be supplied to the strategy - in this case it should be {@link DidMethodEnum#WEBVH_1_0}.
 */
@SuppressWarnings({"PMD.ExcessiveImports", "PMD.AvoidFieldNameMatchingMethodName"})
@Builder
@Getter
public class WebVerifiableHistoryCreator extends AbstractDidLogEntryBuilder implements DidLogCreatorStrategy {

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
     *
     * @deprecated Use {@link #assertionMethods} instead
     */
    @Getter(AccessLevel.PRIVATE)
    @Deprecated(since = "1.9.0")
    private Map<String, String> assertionMethodKeys;

    /**
     * Yet another <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent method</a> of the class.
     * Introduced for the purpose of supplying <a href="https://www.w3.org/TR/did-1.0/#verification-material">verification material</a>
     * for DID document.
     * More specifically, the focus here is on <a href="https://www.w3.org/TR/did-1.0/#assertion">assertion</a>
     * verification relationships.
     *
     * @since 1.9.0
     */
    @Getter(AccessLevel.PRIVATE)
    private Set<ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod> assertionMethods;

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
     *
     * @deprecated Use {@link #authentications} instead
     */
    @Getter(AccessLevel.PRIVATE)
    @Deprecated(since = "1.9.0")
    private Map<String, String> authenticationKeys;

    /**
     * Yet another <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent method</a> of the class.
     * Introduced for the purpose of supplying <a href="https://www.w3.org/TR/did-1.0/#verification-material">verification material</a>
     * for DID document.
     * More specifically, the focus here is on <a href="https://www.w3.org/TR/did-1.0/#authentication">authentication</a>
     * verification relationships.
     * <p>
     * This is an alternative and more potent method to supply the verification material.
     * Eventually, all the keys supplied one way or another are simply combined into a distinct list of values.
     * <p>
     * HINT: Use available {@link ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod} static factory methods to supply public keys.
     *
     * @since 1.9.0
     */
    @Getter(AccessLevel.PRIVATE)
    private Set<ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod> authentications;

    /**
     * Replaces the depr. {@link #verificationMethodKeyProvider},
     * but gets NO precedence over it (if both called against the same object).
     */
    @Getter(AccessLevel.PRIVATE)
    private VcDataIntegrityCryptographicSuite cryptographicSuite;

    /**
     * @deprecated Use {@link #cryptographicSuite} instead
     */
    @Getter(AccessLevel.PRIVATE)
    @Deprecated(since = "1.8.0")
    private VcDataIntegrityCryptographicSuite verificationMethodKeyProvider;

    /**
     * Holder of the <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">updateKeys</a>
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
     * As specified by <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">didwebvh-did-method-parameters</a>, that is:
     * <ul>
     * <li><pre>
     * Once the nextKeyHashes parameter has been set to a non-empty array, Key Pre-Rotation is active.
     * </pre></li>
     * <li><pre>
     * The value of nextKeyHashes MAY be set to an empty array ([]) to deactivate pre-rotation.
     * </pre></li>
     * </ul>
     * <p>
     * This is an alternative and more potent method to supply the parameter.
     * Eventually, all the keys supplied one way or another are simply combined into a distinct list of values.
     * <p>
     * HINT: Use available {@link NextKeyHashesDidMethodParameter} static factory methods to supply public keys.
     *
     * @since 1.8.0
     */
    @Getter(AccessLevel.PACKAGE)
    private Set<NextKeyHashesDidMethodParameter> nextKeyHashesDidMethodParameter;

    /**
     * @deprecated Removed as redundant
     */
    @Getter(AccessLevel.PRIVATE)
    @Deprecated(since = "1.9.0")
    private boolean forceOverwrite;

    /**
     * Holder of the <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">updateKeys</a>
     * DID method parameter:
     * <pre>
     * A JSON array of multikey formatted public keys associated with the private keys that are authorized to sign the log entries that update the DID.
     * </pre>
     *
     * @deprecated Use the {@link #updateKeysDidMethodParameter} setter instead
     */
    @Getter(AccessLevel.PRIVATE)
    @Deprecated(since = "1.8.0")
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
     * @deprecated Use the {@link #nextKeyHashesDidMethodParameter} setter instead
     */
    @Getter(AccessLevel.PRIVATE)
    @Deprecated(since = "1.8.0")
    private Set<File> nextKeys;

    /**
     * A static helper aiming at creation of a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>
     * DID log featuring cryptographic key material from the supplied {@link DidDoc}.
     *
     * @param cryptoSuite
     * @param didDoc                a valid <a href="https://www.w3.org/TR/did-1.0/#did-document-properties">DID document</a>
     *                              object containing cryptographic key material
     * @param identifierRegistryUrl (of a did.jsonl) in its entirety w.r.t.
     *                              <a href="https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation">the-did-to-https-transformation</a>
     * @param zdt                   a date-time with a time-zone in the ISO-8601 calendar system
     * @return a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log
     * @throws DidLogCreatorStrategyException if creation fails for whatever reason
     * @since 1.8.0
     */
    public static String createDidLogFromDidDoc(
            VcDataIntegrityCryptographicSuite cryptoSuite, DidDoc didDoc, URL identifierRegistryUrl, ZonedDateTime zdt)
            throws DidLogCreatorStrategyException {

        var newDidDoc = new JsonObject();

        var ctx = new JsonArray();
        didDoc.getContext().forEach(ctx::add);
        newDidDoc.add("@context", ctx);

        var creator = builder().cryptographicSuite(cryptoSuite).build();

        var did = creator.buildDid(identifierRegistryUrl);

        newDidDoc.addProperty("id", did);

        var authentication = new JsonArray();
        didDoc.getAuthentication().stream()
                .map(vm -> did + "#" + Arrays.stream(vm.getId().split("#")).skip(1).collect(Collectors.joining()))
                .forEach(authentication::add);
        newDidDoc.add("authentication", authentication);

        var assertionMethod = new JsonArray();
        didDoc.getAssertionMethod().stream()
                .map(vm -> did + "#" + Arrays.stream(vm.getId().split("#")).skip(1).collect(Collectors.joining()))
                .forEach(assertionMethod::add);
        newDidDoc.add("assertionMethod", assertionMethod);

        // Collect cryptographic key material from the supplied DID document object and convert it to JSON according to specification
        var verificationMethod = new JsonArray();
        didDoc.getVerificationMethod().stream().map(VerificationMethod::getPublicKeyJwk).forEach(jwk -> {

            var kid = jwk.getKid(); // optional, as specified by https://www.rfc-editor.org/rfc/rfc7517#section-4.5
            if (kid == null || kid.contains("#") || kid.isEmpty()) { // however, in this context required
                throw new IllegalArgumentException("Illegal 'kid' (key ID) parameter detected in the supplied DID document");
            }

            var verificationMethodObj = new JsonObject();
            verificationMethodObj.addProperty("id", did + "#" + kid);

            // CAUTION The "controller" property must not be present w.r.t.:
            // - https://confluence.bit.admin.ch/x/3e0EMw
            verificationMethodObj.addProperty("type", "JsonWebKey2020");

            // CAUTION The "publicKeyMultibase" property must not be present w.r.t.:
            // - https://confluence.bit.admin.ch/x/3e0EMw

            var jwkJsonObj = new JsonObject();

            jwkJsonObj.addProperty("kid", kid);

            var kty = jwk.getKty(); // optional
            if (kty != null) {
                jwkJsonObj.addProperty("kty", kty);
            }

            var crv = jwk.getCrv(); // optional
            if (crv != null) {
                jwkJsonObj.addProperty("crv", crv);
            }

            var x = jwk.getX(); // optional
            if (x != null) {
                jwkJsonObj.addProperty("x", x);
            }

            var y = jwk.getY(); // optional
            if (y != null) {
                jwkJsonObj.addProperty("y", y);
            }

            verificationMethodObj.add("publicKeyJwk", jwkJsonObj);

            verificationMethod.add(verificationMethodObj);
        });

        newDidDoc.add("verificationMethod", verificationMethod);

        return creator.createDidLog(newDidDoc, zdt); // may throw DidLogCreatorStrategyException
    }

    /**
     * Aggregates verification material from various sources, hence it should be exclusively used in this class instead of
     * the {@link #authentications} getter.
     *
     * @since 1.9.0
     */
    private Set<ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod> authentications() throws DidLogCreatorStrategyException {
        var set = new HashSet<ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod>();
        if (this.authenticationKeys != null) { // collect all from deprecated class member
            for (var entry : this.authenticationKeys.entrySet()) {
                try {
                    set.add(ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod.of(entry.getKey(), entry.getValue()));
                } catch (VerificationMethodException e) {
                    throw new DidLogCreatorStrategyException(e);
                }
            }
        }

        if (this.authentications != null) {
            set.addAll(authentications);
        }

        return set;
    }

    /**
     * Aggregates verification material from various sources, hence it should be exclusively used in this class instead of
     * the {@link #assertionMethods} getter.
     *
     * @since 1.9.0
     */
    private Set<ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod> assertionMethods() throws DidLogCreatorStrategyException {
        var set = new HashSet<ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod>();
        if (this.assertionMethodKeys != null) { // collect all from deprecated class member
            for (var entry : this.assertionMethodKeys.entrySet()) {
                try {
                    set.add(ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod.of(entry.getKey(), entry.getValue()));
                } catch (VerificationMethodException e) {
                    throw new DidLogCreatorStrategyException(e);
                }
            }
        }

        if (this.assertionMethods != null) {
            set.addAll(assertionMethods);
        }

        return set;
    }

    /**
     * Aggregates all <a href="https://identity.foundation/didwebvh/v0.3/#didwebvh-did-method-parameters">updateKeys</a>
     * DID method parameter values supplied from various sources, hence it should be exclusively used in this class instead of
     * the {@link #updateKeysDidMethodParameter} getter.
     *
     * @since 1.9.0
     */
    private Set<UpdateKeysDidMethodParameter> updateKeysDidMethodParameter() throws DidLogCreatorStrategyException {

        var set = new HashSet<UpdateKeysDidMethodParameter>();
        if (this.updateKeys != null) { // collect all from deprecated class member
            for (var key : this.updateKeys) {
                try {
                    set.add(UpdateKeysDidMethodParameter.of(key.toPath()));
                } catch (UpdateKeysDidMethodParameterException e) {
                    throw new DidLogCreatorStrategyException(e);
                }
            }
        }

        if (this.updateKeysDidMethodParameter != null) {
            set.addAll(updateKeysDidMethodParameter);
        }

        return set;
    }

    /**
     * Aggregates all <a href="https://identity.foundation/didwebvh/v0.3/#didwebvh-did-method-parameters">nextKeyHashes</a>
     * DID method parameter values supplied from various sources, hence it should be exclusively used in this class instead of
     * the {@link #nextKeyHashesDidMethodParameter} getter.
     *
     * @return a set of {@link NextKeyHashesDidMethodParameter} objects, never {@code null}
     * @since 1.9.0
     */
    private Set<NextKeyHashesDidMethodParameter> nextKeyHashesDidMethodParameter() throws DidLogCreatorStrategyException {

        var set = new HashSet<NextKeyHashesDidMethodParameter>();
        if (this.nextKeys != null) { // collect all from deprecated class member
            for (var key : this.nextKeys) {
                try {
                    set.add(NextKeyHashesDidMethodParameter.of(key.toPath()));
                } catch (NextKeyHashesDidMethodParameterException e) {
                    throw new DidLogCreatorStrategyException(e);
                }
            }
        }

        if (this.nextKeyHashesDidMethodParameter != null) {
            set.addAll(nextKeyHashesDidMethodParameter);
        }

        return set;
    }

    private VcDataIntegrityCryptographicSuite getCryptoSuite() {
        if (this.verificationMethodKeyProvider != null) {
            return this.verificationMethodKeyProvider;
        }

        return this.cryptographicSuite;
    }

    @Override
    protected DidMethodEnum getDidMethod() {
        return DidMethodEnum.WEBVH_1_0;
    }

    /**
     * Creates a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log by taking into account other
     * features of this {@link WebVerifiableHistoryCreator} object, optionally customized by previously calling fluent methods like
     * {@link WebVerifiableHistoryCreator#verificationMethodKeyProvider}, {@link WebVerifiableHistoryCreator#authentications} or
     * {@link WebVerifiableHistoryCreator#assertionMethods}.
     *
     * @param identifierRegistryUrl is the URL of a did.jsonl in its entirety w.r.t.
     *                              <a href="https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation">the-did-to-https-transformation</a>
     * @return a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log
     * @throws DidLogCreatorStrategyException        if creation fails for whatever reason
     * @throws IncompleteDidLogEntryBuilderException if either no cryptographic suite or no proper verification material has been supplied yet
     * @see #createDidLog(URL, ZonedDateTime)
     */
    @Override
    public String createDidLog(URL identifierRegistryUrl) throws DidLogCreatorStrategyException {
        return createDidLog(identifierRegistryUrl, ZonedDateTime.now());
    }

    /**
     * Creates a <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <p>
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param identifierRegistryUrl (of a did.jsonl) in its entirety w.r.t.
     *                              <a href="https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation">the-did-to-https-transformation</a>
     * @param zdt                   a date-time with a time-zone in the ISO-8601 calendar system
     * @return a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log
     * @throws DidLogCreatorStrategyException        if creation fails for whatever reason
     * @throws IncompleteDidLogEntryBuilderException if either no cryptographic suite or no proper verification material has been supplied yet
     */
    @Override
    public String createDidLog(URL identifierRegistryUrl, ZonedDateTime zdt) throws DidLogCreatorStrategyException {

        // Create initial did doc with placeholder
        return createDidLog(createDidDoc(identifierRegistryUrl, this.authentications(), this.assertionMethods()), zdt);
    }

    //@SuppressWarnings({"PMD.CyclomaticComplexity"})
    private String createDidLog(JsonObject didDoc, ZonedDateTime zdt) throws DidLogCreatorStrategyException {

        if (getCryptoSuite() == null) {
            throw new IncompleteDidLogEntryBuilderException("No cryptographic suite supplied");
        }

        // since did:tdw:0.4 ("Changes the DID log entry array to be named JSON objects or properties.")
        var didLogEntryWithoutProofAndSignature = new JsonObject();

        // Add a preliminary versionId value
        // The first item in the input JSON array MUST be the placeholder string {SCID}.
        didLogEntryWithoutProofAndSignature.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, SCID_PLACEHOLDER);
        // Add the versionTime value
        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        didLogEntryWithoutProofAndSignature.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME, DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));

        // Define the parameters (https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters)
        // The third item in the input JSON array MUST be the parameters JSON object.
        // The parameters are used to configure the DID generation and verification processes.
        // All parameters MUST be valid and all required values in the first version of the DID MUST be present.
        didLogEntryWithoutProofAndSignature.add(DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS,
                createDidParams(this.getCryptoSuite(),
                        this.updateKeysDidMethodParameter(),
                        this.nextKeyHashesDidMethodParameter()));

        // The JSON object "state" contains the DIDDoc for this version of the DID.
        didLogEntryWithoutProofAndSignature.add(DID_LOG_ENTRY_JSON_PROPERTY_STATE, didDoc);

        // Generate SCID and replace placeholder in did doc
        String scid = buildSCID(didLogEntryWithoutProofAndSignature);

        /* https://identity.foundation/didwebvh/v1.0/#output-of-the-scid-generation-process:
        After the SCID is generated, the literal {SCID} placeholders are replaced by the generated SCID value (below).
        This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        Once the process has run, the version number of this first version of the DID (1),
        a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
         */

        var didLogEntryWithSCIDWithoutProofAndSignature = JsonParser.parseString(
                didLogEntryWithoutProofAndSignature.toString().replace(SCID_PLACEHOLDER, scid)
        ).getAsJsonObject();

        // See https://identity.foundation/didwebvh/v1.0/#generate-entry-hash
        // After the SCID is generated, the literal {SCID} placeholders are replaced by the generated SCID value (below).
        // This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        // Once the process has run, the version number of this first version of the DID (1),
        // a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
        String entryHash = buildSCID(didLogEntryWithSCIDWithoutProofAndSignature);

        // since did:tdw:0.4 ("Changes the DID log entry array to be named JSON objects or properties.")
        var didLogEntryWithoutProof = new JsonObject();

        var challenge = "1-" + entryHash; // versionId as the proof challenge
        didLogEntryWithoutProof.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, challenge);
        didLogEntryWithoutProof.add(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME,
                didLogEntryWithSCIDWithoutProofAndSignature.get(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME));
        didLogEntryWithoutProof.add(DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS,
                didLogEntryWithSCIDWithoutProofAndSignature.get(DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS));
        didLogEntryWithoutProof.add(DID_LOG_ENTRY_JSON_PROPERTY_STATE,
                didLogEntryWithSCIDWithoutProofAndSignature.get(DID_LOG_ENTRY_JSON_PROPERTY_STATE));

        /*
        https://identity.foundation/didwebvh/v1.0/#create-register:
        "5.5. Generate the Data Integrity proof: A Data Integrity proof on the preliminary JSON object as updated in the
        previous step MUST be generated using an authorized key in the required updateKeys property in the parameters
        object and the proofPurpose set to assertionMethod."
        Since did.tdw:0.4 ->
            "Makes each DID version’s Data Integrity proof apply across the JSON DID log entry object, as is typical with Data Integrity proofs.
            Previously, the Data Integrity proof was generated across the current DIDDoc version, with the versionId as the challenge."
         */
        try {
            var didLogEntry = this.getCryptoSuite().addProof(
                    didLogEntryWithoutProof.toString(), null, JCSHasher.PROOF_PURPOSE_ASSERTION_METHOD, zdt);

            WebVerifiableHistoryDidLogMetaPeeker.peek(didLogEntry).getDidDoc().getId(); // sanity check

            return didLogEntry;
        } catch (VcDataIntegrityCryptographicSuiteException exc) {
            throw new DidLogCreatorStrategyException(exc);
        } catch (DidLogMetaPeekerException exc) {
            throw new DidLogCreatorStrategyException("Creating a DID log resulted in unresolvable/unverifiable DID log", exc);
        }
    }
}