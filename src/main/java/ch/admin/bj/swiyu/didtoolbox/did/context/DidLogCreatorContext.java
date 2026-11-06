package ch.admin.bj.swiyu.didtoolbox.did.context;

import ch.admin.bj.swiyu.didtoolbox.cryptography.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.did.IncompleteDidLogEntryBuilderException;
import ch.admin.bj.swiyu.didtoolbox.did.VerificationMethodKeyProvider;
import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethod;
import lombok.Builder;
import lombok.Getter;

import java.net.URL;
import java.time.ZonedDateTime;
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
 * <li>{@link DidLogCreatorContext#authentications} for setting authentication
 * (P-256/Ed25519 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link DidLogCreatorContext#assertionMethods} for setting/assertion
 * (P-256/Ed25519 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * </ul>
 * To load required (Ed25519) keys (e.g. from the file system in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format),
 * feel free to explore all available {@link VerificationMethodKeyProvider} implementations.
 * <p>
 * To load authentication/assertion public P-256/Ed25519 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a> keys from
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">PEM</a> files, you may rely on {@link JwkUtils}.
 * <p>
 * For instance:
 * <pre>
 * {@code
 *     package mypackage;
 *
 *     import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
 *     import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorContext;
 *     import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
 *     import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethod;
 *
 *     import java.net.URI;
 *     import java.net.URL;
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
 *             didLogEntryWithExternalKeys = DidLogCreatorContext.builder(
 *                         DidMethodEnum.WEBVH_1_0,
 *                         new EdDsaJcs2022VcDataIntegrityCryptographicSuite(Path.of("src/test/data/private.pem")))
 *                     .assertionMethods(Set.of(VerificationMethod.of(
 *                             "my-assert-key-01", Path.of("src/test/data/assert-key-01.pub")
 *                     )))
 *                     .authentications(Set.of(VerificationMethod.of(
 *                             "my-auth-key-01", Path.of("src/test/data/auth-key-01.pub")
 *                     )))
 *                     .build()
 *                     .create(identifierRegistryUrl);
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
     * Constructs a builder for creating did logs with the provided crypto suite
     * @param method version of the did log (WEBVH or TDW)
     * @param cryptoSuite used to create the log entry signature
     * @return the builder, it's recommended to also call 'assertionMethods' or 'authentications' on it.
     */
    public static DidLogCreatorContextBuilder builder(DidMethodEnum method, VcDataIntegrityCryptographicSuite cryptoSuite) {
        return new DidLogCreatorContextBuilder().didMethod(method).cryptographicSuite(cryptoSuite);
    }

    /**
     * Yet another <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent method</a> of the class.
     * Introduced for the purpose of supplying <a href="https://www.w3.org/TR/did-1.0/#verification-material">verification material</a>
     * for DID document.
     * More specifically, the focus here is on <a href="https://www.w3.org/TR/did-1.0/#assertion">assertion</a>
     * verification relationships.
     *
     * @since 1.9.0
     */
    @Builder.Default
    @Getter()
    private Set<VerificationMethod> assertionMethods = Set.of();

    /**
     * Yet another <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent method</a> of the class.
     * Introduced for the purpose of supplying <a href="https://www.w3.org/TR/did-1.0/#verification-material">verification material</a>
     * for DID document.
     * More specifically, the focus here is on <a href="https://www.w3.org/TR/did-1.0/#authentication">authentication</a>
     * verification relationships.
     *
     * @since 1.9.0
     */
    @Builder.Default
    @Getter()
    private Set<VerificationMethod> authentications = Set.of();

    /**
     * Handles creation of the vc data integrity proof
     *
     * @since 1.8.0
     */
    @Getter()
    private VcDataIntegrityCryptographicSuite cryptographicSuite;

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
    @Builder.Default
    @Getter()
    private Set<UpdateKeysDidMethodParameter> updateKeysDidMethodParameter = Set.of();

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
    @Builder.Default
    @Getter()
    private Set<NextKeyHashesDidMethodParameter> nextKeyHashesDidMethodParameter = Set.of();

    /**
     * Default = {@link DidMethodEnum#WEBVH_1_0}
     */
    @Builder.Default
    private DidMethodEnum didMethod = DidMethodEnum.WEBVH_1_0;

    /**
     * Creates a valid DID log by taking into account other
     * features of this {@link DidLogCreatorContext} object, optionally customized by previously calling fluent methods like
     * {@link DidLogCreatorContext#cryptographicSuite}, {@link DidLogCreatorContext#authentications} or
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