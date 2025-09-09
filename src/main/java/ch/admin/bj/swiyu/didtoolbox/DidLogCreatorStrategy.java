package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryCreator;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryCreatorException;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Set;

/**
 * {@link DidLogCreatorStrategy} is the class in charge of DID log generation in specification-agnostic fashion
 * i.e. regardless of DID method specification.
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@link #builder()} method.
 * <p>
 * Once a {@link DidLogCreatorStrategy} object is "built", creating a DID
 * log goes simply by calling {@link #create(URL)} method. Optionally, but most likely, an already existing key material will
 * be also used in the process, so for the purpose there are further fluent methods available:
 * <ul>
 * <li>{@link DidLogCreatorStrategy.DidLogCreatorStrategyBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} for setting the update (Ed25519) key</li>
 * <li>{@link DidLogCreatorStrategy.DidLogCreatorStrategyBuilder#authenticationKeys(Map)} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link DidLogCreatorStrategy.DidLogCreatorStrategyBuilder#assertionMethodKeys(Map)} for setting/assertion
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
 * For instance:
 * <pre>
 * {@code
 *     package mypackage;
 *
 *     import ch.admin.bj.swiyu.didtoolbox.*;
 *     import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
 *     import java.net.*;
 *
 *     public static void main(String... args) {
 *
 *         String didLogEntryWithGeneratedKeys = null;
 *         String didLogEntryWithExternalKeys = null;
 *         try {
 *             URL identifierRegistryUrl = URL.of(new URI("https://127.0.0.1:54858/123456789/123456789/did.jsonl"), null);
 *
 *             // NOTE that all required keys will be generated here as well, as no explicit verificationMethodKeyProvider is set
 *             didLogEntryWithGeneratedKeys = DidLogCreatorStrategy.builder()
 *                 .build()
 *                 .create(identifierRegistryUrl);
 *
 *             // Using already existing key material
 *             didLogEntryWithExternalKeys = DidLogCreatorStrategy.builder()
 *                 .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new File("private-key.pem"), new File("public-key.pem")))
 *                 .assertionMethodKeys(Map.of(
 *                     "my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("assert-key-01.pub"), "my-assert-key-01")
 *                 ))
 *                 .authenticationKeys(Map.of(
 *                     "my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("auth-key-01.pub"), "my-auth-key-01")
 *                 ))
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
public class DidLogCreatorStrategy {

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
    @Getter(AccessLevel.PRIVATE)
    private boolean forceOverwrite;

    @Builder.Default
    private DidMethodEnum didMethod = DidMethodEnum.WEBVH_1_0;

    /**
     * Creates a valid DID log by taking into account other
     * features of this {@link DidLogCreatorStrategy} object, optionally customized by previously calling fluent methods like
     * {@link DidLogCreatorStrategy.DidLogCreatorStrategyBuilder#verificationMethodKeyProvider}, {@link DidLogCreatorStrategy.DidLogCreatorStrategyBuilder#authenticationKeys(Map)} or
     * {@link DidLogCreatorStrategy.DidLogCreatorStrategyBuilder#assertionMethodKeys(Map)}.
     *
     * @param identifierRegistryUrl is the URL of a did.jsonl in its entirety w.r.t.
     *                              <a href="https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation">he-did-to-https-transformation</a>
     * @return a valid DID log
     * @throws IOException if creation fails for whatever reason
     * @see #create(URL, ZonedDateTime)
     */
    public String create(URL identifierRegistryUrl) throws DidLogCreatorStrategyException, TdwCreatorException, IOException {
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
     * @return
     * @throws DidLogCreatorStrategyException
     */
    String create(URL identifierRegistryUrl, ZonedDateTime zdt) throws DidLogCreatorStrategyException, TdwCreatorException {

        switch (didMethod) {
            case TDW_0_3 -> {
                try {
                    return TdwCreator.builder()
                            .verificationMethodKeyProvider(verificationMethodKeyProvider)
                            .assertionMethodKeys(assertionMethodKeys)
                            .authenticationKeys(authenticationKeys)
                            .updateKeys(updateKeys)
                            .forceOverwrite(forceOverwrite)
                            .build()
                            .create(identifierRegistryUrl, zdt);
                } catch (IOException e) {
                    throw new DidLogCreatorStrategyException(e);
                }
            }
            case WEBVH_1_0 -> {
                try {
                    return WebVerifiableHistoryCreator.builder()
                            .verificationMethodKeyProvider(verificationMethodKeyProvider)
                            .assertionMethodKeys(assertionMethodKeys)
                            .authenticationKeys(authenticationKeys)
                            .updateKeys(updateKeys)
                            .forceOverwrite(forceOverwrite)
                            .build()
                            .create(identifierRegistryUrl, zdt);
                } catch (WebVerifiableHistoryCreatorException e) {
                    throw new DidLogCreatorStrategyException(e);
                }
            }
            default -> throw new DidLogCreatorStrategyException("The supplied DID log features an unsupported DID method");
        }
    }
}