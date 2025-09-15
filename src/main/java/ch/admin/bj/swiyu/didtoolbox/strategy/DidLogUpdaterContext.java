package ch.admin.bj.swiyu.didtoolbox.strategy;

import ch.admin.bj.swiyu.didtoolbox.Ed25519VerificationMethodKeyProviderImpl;
import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.VerificationMethodKeyProvider;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
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
 * it is intended to be instantiated exclusively via its static {@link #builder()} method.
 * <p>
 * Once a {@link DidLogUpdaterContext} object is "built", creating a DID
 * log goes simply by calling {@link #update(String)} method. Optionally, but most likely, an already existing key material will
 * be also used in the process, so for the purpose there are further fluent methods available:
 * <ul>
 * <li>{@link DidLogUpdaterContext.DidLogUpdaterContextBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} for setting the update (Ed25519) key</li>
 * <li>{@link DidLogUpdaterContext.DidLogUpdaterContextBuilder#authenticationKeys(Map)} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link DidLogUpdaterContext.DidLogUpdaterContextBuilder#assertionMethodKeys(Map)} for setting/assertion
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
 *     import ch.admin.bj.swiyu.didtoolbox.strategy.*;
 *     import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
 *     import java.net.*;
 *
 *     public static void main(String... args) {
 *
 *         String initialDidLogEntryWithGeneratedKeys = null;
 *         String updatedDidLogEntryWithReplacedVerificationMaterial = null;
 *         try {
 *             URL identifierRegistryUrl = URL.of(new URI("https://127.0.0.1:54858/123456789/123456789/did.jsonl"), null);
 *             var verificationMethodKeyProvider = new Ed25519VerificationMethodKeyProviderImpl(new File("src/test/data/private.pem"), new File("src/test/data/public.pem"));
 *
 *             // NOTE that all verification material will be generated here as well
 *             initialDidLogEntryWithGeneratedKeys = DidLogCreatorContext.builder()
 *                 .verificationMethodKeyProvider(verificationMethodKeyProvider)
 *                 .build()
 *                 .create(identifierRegistryUrl);
 *
 *             // Now update the previously generated initial single-entry DID log
 *             updatedDidLogEntryWithReplacedVerificationMaterial = DidLogUpdaterContext.builder()
 *                 .didMethod(DidMethodEnum.detectDidMethod(initialDidLogEntryWithGeneratedKeys))
 *                 .verificationMethodKeyProvider(verificationMethodKeyProvider) // the same used during creation
 *                 .assertionMethodKeys(Map.of(
 *                     "my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-01")
 *                 ))
 *                 .authenticationKeys(Map.of(
 *                     "my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-01")
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

    @Getter(AccessLevel.PACKAGE)
    private Map<String, String> assertionMethodKeys;
    @Getter(AccessLevel.PACKAGE)
    private Map<String, String> authenticationKeys;
    @Builder.Default
    @Getter(AccessLevel.PACKAGE)
    private VerificationMethodKeyProvider verificationMethodKeyProvider = new Ed25519VerificationMethodKeyProviderImpl();
    @Getter(AccessLevel.PACKAGE)
    private Set<File> updateKeys;

    @Builder.Default
    private DidMethodEnum didMethod = DidMethodEnum.WEBVH_1_0;

    /**
     * Updates a valid DID log by taking into account other
     * features of this {@link DidLogUpdaterContext} object, optionally customized by previously calling fluent methods like
     * {@link DidLogUpdaterContext.DidLogUpdaterContextBuilder#verificationMethodKeyProvider}, {@link DidLogUpdaterContext.DidLogUpdaterContextBuilder#authenticationKeys(Map)} or
     * {@link DidLogUpdaterContext.DidLogUpdaterContextBuilder#assertionMethodKeys(Map)}.
     *
     * @param didLog to update. Expected to be resolvable/verifiable already.
     * @return a whole new DID log entry to be appended to the existing {@code didLog}
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason.
     * @see #update(String, ZonedDateTime)
     */
    public String update(String didLog) throws DidLogUpdaterStrategyException {
        return update(didLog, ZonedDateTime.now());
    }

    /**
     * The file-system-as-input variation of {@link #update(String)}
     *
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason
     * @see #update(String, ZonedDateTime)
     */
    public String update(File didLogFile) throws DidLogUpdaterStrategyException {
        try {
            return update(Files.readString(didLogFile.toPath()), ZonedDateTime.now());
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
     * @throws DidLogUpdaterStrategyException if update fails for whatever reason.
     */
    String update(String resolvableDidLog, ZonedDateTime zdt) throws DidLogUpdaterStrategyException {
        // just use the strategy factory to get an adequate strategy
        return DidLogStrategyFactory.getUpdaterStrategy(this).updateDidLog(resolvableDidLog, zdt);
    }
}