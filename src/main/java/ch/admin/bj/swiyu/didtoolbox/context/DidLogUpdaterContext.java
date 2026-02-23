package ch.admin.bj.swiyu.didtoolbox.context;

import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.VerificationMethodKeyProvider;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Set;

/**
 * {@link DidLogUpdaterContext} is the class in charge of DID log update (rotate) in specification-agnostic fashion
 * i.e. regardless of DID method specification.
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@code builder()} method.
 * <p>
 * Once a {@link DidLogUpdaterContext} object is properly "built"
 * (i.e. with some proper cryptographic suite and verification material included),
 * creating a DID log goes simply by calling {@link #update(String)} method.
 * So, before calling the {@code build()} method there are also these fluent methods available:
 * <ul>
 * <li>{@link DidLogUpdaterContext#cryptographicSuite} for the purpose of adding data integrity proof</li>
 * <li>{@link DidLogUpdaterContext#authenticationKeys} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link DidLogUpdaterContext#assertionMethodKeys} for setting/assertion
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * </ul>
 * To load required (Ed25519) keys (e.g. from the file system in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format),
 * feel free to explore all available {@link VerificationMethodKeyProvider} implementations.
 * <p>
 * To load authentication/assertion public EC P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a> keys from
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">PEM</a> files, you may rely on {@link JwkUtils}.
 * <p>
 * For instance:
 * <pre>
 * {@code
 *     package mypackage;
 *
 *     import ch.admin.bj.swiyu.didtoolbox.*;
 *     import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
 *     import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext;
 *     import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
 *     import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
 *
 *     import java.net.*;
 *     import java.nio.file.Path;
 *     import java.util.Set;
 *
 *     public static void main(String... args) {
 *
 *         String initialDidLogEntryWithGeneratedKeys = null;
 *         String updatedDidLogEntryWithReplacedVerificationMaterial = null;
 *         try {
 *             URL identifierRegistryUrl = URL.of(new URI("https://127.0.0.1:54858/123456789/123456789/did.jsonl"), null);
 *             var cryptographicSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(Path.of("src/test/data/private.pem"));
 *
 *             initialDidLogEntryWithGeneratedKeys = DidLogCreatorContext.builder()
 *                 .cryptographicSuite(cryptographicSuite)
 *                 .assertionMethodKeys(Map.of(
 *                     "my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/assert-key-01.pub"), "my-assert-key-01")
 *                 ))
 *                 .build()
 *                 .create(identifierRegistryUrl);
 *
 *             // Now update the previously generated initial single-entry DID log
 *             updatedDidLogEntryWithReplacedVerificationMaterial = DidLogUpdaterContext.builder()
 *                 .didMethod(DidMethodEnum.detectDidMethod(initialDidLogEntryWithGeneratedKeys))
 *                 .cryptographicSuite(cryptographicSuite) // the same used during creation
 *                 .assertionMethodKeys(Map.of(
 *                     "my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/assert-key-01.pub"), "my-assert-key-01")
 *                 ))
 *                 .authenticationKeys(Map.of(
 *                     "my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(Path.of("src/test/data/auth-key-01.pub"), "my-auth-key-01")
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
public class DidLogUpdaterContext {

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
    @Getter(AccessLevel.PACKAGE)
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
    @Getter(AccessLevel.PACKAGE)
    private Map<String, String> authenticationKeys;

    /**
     * Replaces the depr. {@link #verificationMethodKeyProvider},
     * but gets no precedence over it (if both called against the same object).
     */
    @Getter(AccessLevel.PRIVATE)
    private VcDataIntegrityCryptographicSuite cryptographicSuite;

    /**
     * @deprecated Use {@link #cryptographicSuite} instead. Since 1.8.0
     */
    @Getter(AccessLevel.PRIVATE)
    @Deprecated
    private VcDataIntegrityCryptographicSuite verificationMethodKeyProvider;

    /**
     * Holder of the <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">updateKeys</a>
     * DID method parameter:
     * <pre>
     * A JSON array of multikey formatted public keys associated with the private keys that are authorized to sign the log entries that update the DID.
     * </pre>
     * <p>
     * HINT: Use available {@link UpdateKeysDidMethodParameter} static factory methods to supply public keys.
     *
     * @since 1.8.0
     */
    @Getter(AccessLevel.PACKAGE)
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
     * HINT: Use available {@link UpdateKeysDidMethodParameter} static factory methods to supply public keys.
     *
     * @since 1.8.0
     */
    @Getter(AccessLevel.PACKAGE)
    private Set<NextKeyHashesDidMethodParameter> nextKeyHashesDidMethodParameter;

    /**
     * Default = {@link DidMethodEnum#WEBVH_1_0}
     */
    @Builder.Default
    private DidMethodEnum didMethod = DidMethodEnum.WEBVH_1_0;

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
    @Deprecated(since = "1.8.0")
    void nextKeys(Set<File> pemFiles) throws NextKeyHashesDidMethodParameterException {
        nextKeyHashesDidMethodParameter.addAll(NextKeyHashesDidMethodParameter.of(pemFiles));
    }

    /**
     * Holder of the <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">updateKeys</a>
     * DID method parameter:
     * <pre>
     * A JSON array of multikey formatted public keys associated with the private keys that are authorized to sign the log entries that update the DID.
     * </pre>
     *
     * @deprecated Use {@link #updateKeysDidMethodParameter} instead
     */
    @Deprecated(since = "1.8.0")
    void updateKeys(Set<File> pemFiles) throws UpdateKeysDidMethodParameterException {
        updateKeysDidMethodParameter.addAll(UpdateKeysDidMethodParameter.of(pemFiles));
    }

    VcDataIntegrityCryptographicSuite getCryptoSuite() {
        if (this.verificationMethodKeyProvider != null) {
            return this.verificationMethodKeyProvider;
        }

        return this.cryptographicSuite;
    }

    /**
     * Updates a valid DID log by taking into account other
     * features of this {@link DidLogUpdaterContext} object, optionally customized by previously calling fluent methods like
     * {@link DidLogUpdaterContext#verificationMethodKeyProvider}, {@link DidLogUpdaterContext#authenticationKeys} or
     * {@link DidLogUpdaterContext#assertionMethodKeys}.
     *
     * @param didLog to update. Expected to be resolvable/verifiable already.
     * @return a whole new DID log entry to be appended to the existing {@code didLog}
     * @throws DidLogUpdaterStrategyException        if update fails for whatever reason.
     * @throws IncompleteDidLogEntryBuilderException if either no cryptographic suite or no proper verification material has been supplied yet
     * @see #update(String, ZonedDateTime)
     */
    public String update(String didLog) throws DidLogUpdaterStrategyException {
        return update(didLog, ZonedDateTime.now());
    }

    /**
     * The file-system-as-input variation of {@link #update(String)}
     *
     * @return a whole new DID log entry to be appended to the supplied {@code didLogFile}
     * @throws DidLogUpdaterStrategyException        if update fails for whatever reason
     * @throws IncompleteDidLogEntryBuilderException if either no cryptographic suite or no proper verification material has been supplied yet
     * @see #update(String, ZonedDateTime)
     */
    public String update(File didLogFile) throws DidLogUpdaterStrategyException {
        try {
            return update(Files.readString(didLogFile.toPath()));
        } catch (IOException e) {
            throw new DidLogUpdaterStrategyException(e);
        }
    }

    /**
     * Updates a valid DID log for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <p>
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param resolvableDidLog to update. Expected to be resolvable/verifiable already.
     * @param zdt              a date-time with a time-zone in the ISO-8601 calendar system
     * @return a whole new DID log entry to be appended to the existing {@code didLog}
     * @throws DidLogUpdaterStrategyException        if update fails for whatever reason.
     * @throws IncompleteDidLogEntryBuilderException if either no cryptographic suite or no proper verification material has been supplied yet
     */
    String update(String resolvableDidLog, ZonedDateTime zdt) throws DidLogUpdaterStrategyException {
        // just use the strategy factory to get an adequate strategy
        return DidLogStrategyFactory.getUpdaterStrategy(this).updateDidLog(resolvableDidLog, zdt);
    }
}