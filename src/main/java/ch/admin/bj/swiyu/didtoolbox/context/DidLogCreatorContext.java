package ch.admin.bj.swiyu.didtoolbox.context;

import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.VerificationMethodKeyProvider;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.io.File;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * {@link DidLogCreatorContext} is the class in charge of DID log generation in specification-agnostic fashion
 * i.e. regardless of DID method specification.
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@code builder()} method.
 * <p>
 * Once a {@link DidLogCreatorContext} object is properly "built"
 * (i.e. with some proper cryptographic suite and verification material included),
 * creating a DID log goes simply by calling {@link #create(URL)} method.
 * So, before calling the {@code build()} method there are also these fluent methods available:
 * <ul>
 * <li>{@link DidLogCreatorContext#cryptographicSuite} for the purpose of adding data integrity proof</li>
 * <li>{@link DidLogCreatorContext#authenticationKeys} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link DidLogCreatorContext#assertionMethods} for setting/assertion
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
 *     import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
 *     import ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod;
 *     import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
 *
 *     import java.net.*;
 *     import java.nio.file.Path;
 *     import java.util.Set;
 *
 *     public static void main(String... args) {
 *
 *         String didLogEntryWithGeneratedKeys = null;
 *         String didLogEntryWithExternalKeys = null;
 *         try {
 *             URL identifierRegistryUrl = URL.of(new URI("https://127.0.0.1:54858/123456789/123456789/did.jsonl"), null);
 *
 *             // Using already existing key material
 *             didLogEntryWithExternalKeys = DidLogCreatorContext.builder()
 *                 .cryptographicSuite(new EdDsaJcs2022VcDataIntegrityCryptographicSuite(Path.of("src/test/data/private.pem")))
 *                 .assertionMethods(Set.of(VerificationMethod.of(
 *                     "my-assert-key-01", Path.of("src/test/data/assert-key-01.pub")
 *                 )))
 *                 .authentications(Set.of(VerificationMethod.of(
 *                     "my-auth-key-01", Path.of("src/test/data/auth-key-01.pub")
 *                 )))
 *                 .build()
 *                 .create(identifierRegistryUrl);
 *
 *         } catch (Exception e) {
 *             // some exc. handling goes here
 *             System.exit(1);
 *         }
 *
 *         // do something with the didLogEntry* vars here
 *     }
 * }
 * </pre>
 */
@Builder
@Getter
public class DidLogCreatorContext {

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
     * @deprecated Use the {@link #assertionMethods} setter instead
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
     * @deprecated Use the {@link #authentications} setter instead
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
     *
     * @since 1.9.0
     */
    @Getter(AccessLevel.PRIVATE)
    private Set<ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod> authentications;

    /**
     * Replaces the depr. {@link #verificationMethodKeyProvider},
     * but gets no precedence over it (if both called against the same object).
     *
     * @since 1.8.0
     */
    @Getter(AccessLevel.PRIVATE)
    private VcDataIntegrityCryptographicSuite cryptographicSuite;

    /**
     * @deprecated Use the {@link #cryptographicSuite} setter instead
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
     * HINT: Use available {@link NextKeyHashesDidMethodParameter} static factory methods to supply public keys.
     *
     * @since 1.8.0
     */
    @Getter(AccessLevel.PRIVATE)
    private Set<NextKeyHashesDidMethodParameter> nextKeyHashesDidMethodParameter;

    /**
     * @deprecated Removed as redundant
     */
    @Getter(AccessLevel.PACKAGE)
    @Deprecated(since = "1.9.0")
    private boolean forceOverwrite;

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
     * @deprecated Use the {@link #nextKeyHashesDidMethodParameter} setter instead
     */
    @Getter(AccessLevel.PRIVATE)
    @Deprecated(since = "1.8.0")
    private Set<File> nextKeys;

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
     * Aggregates verification material from various sources, hence it should be exclusively used in this class instead of
     * the {@link #authentications} getter.
     *
     * @return a set of {@link ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod} objects, never {@code null}
     * @since 1.9.0
     */
    Set<ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod> authentications() throws DidLogCreatorStrategyException {
        var set = new HashSet<VerificationMethod>();
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
     * @return a set of {@link ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod} objects, never {@code null}
     * @since 1.9.0
     */
    Set<ch.admin.bj.swiyu.didtoolbox.model.VerificationMethod> assertionMethods() throws DidLogCreatorStrategyException {
        var set = new HashSet<VerificationMethod>();
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
     * @return a set of {@link UpdateKeysDidMethodParameter} objects, never {@code null}
     * @since 1.9.0
     */
    Set<UpdateKeysDidMethodParameter> updateKeysDidMethodParameter() throws DidLogCreatorStrategyException {

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
    Set<NextKeyHashesDidMethodParameter> nextKeyHashesDidMethodParameter() throws DidLogCreatorStrategyException {

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

    VcDataIntegrityCryptographicSuite getCryptoSuite() {
        if (this.verificationMethodKeyProvider != null) {
            return this.verificationMethodKeyProvider;
        }

        return this.cryptographicSuite;
    }

    /**
     * Creates a valid DID log by taking into account other
     * features of this {@link DidLogCreatorContext} object, optionally customized by previously calling fluent methods like
     * {@link DidLogCreatorContext#verificationMethodKeyProvider}, {@link DidLogCreatorContext#authenticationKeys} or
     * {@link DidLogCreatorContext#assertionMethods}.
     *
     * @param identifierRegistryUrl is the URL of a did.jsonl in its entirety w.r.t.
     *                              <a href="https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation">the-did-to-https-transformation</a>
     * @return a valid DID log
     * @throws DidLogCreatorStrategyException        if creation fails for whatever reason
     * @throws IncompleteDidLogEntryBuilderException if either no cryptographic suite or no proper verification material has been supplied yet
     * @see #create(URL, ZonedDateTime)
     */
    public String create(URL identifierRegistryUrl) throws DidLogCreatorStrategyException {
        return create(identifierRegistryUrl, ZonedDateTime.now());
    }

    /**
     * Creates a DID log for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <p>
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param identifierRegistryUrl (of a did.jsonl) in its entirety w.r.t.
     *                              <a href="https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation">the-did-to-https-transformation</a>
     * @param zdt                   a date-time with a time-zone in the ISO-8601 calendar system
     * @return a valid DID log
     * @throws DidLogCreatorStrategyException        if creation fails for whatever reason
     * @throws IncompleteDidLogEntryBuilderException if either no cryptographic suite or no proper verification material has been supplied yet
     */
    String create(URL identifierRegistryUrl, ZonedDateTime zdt) throws DidLogCreatorStrategyException {
        // just use the strategy factory to get an adequate strategy
        return DidLogStrategyFactory.getCreatorStrategy(this).createDidLog(identifierRegistryUrl, zdt);
    }
}