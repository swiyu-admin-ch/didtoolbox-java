package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryDeactivator;
import lombok.Builder;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.file.Files;
import java.time.ZonedDateTime;

/**
 * The {@link DidLogDeactivatorStrategy} class is specification-agnostic DID log deactivator.
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@link #builder()} method.
 * <p>
 * Once a {@link DidLogDeactivatorStrategy} object is "built", creating a DID
 * log goes simply by calling {@link #deactivate(String)} method. Optionally, but most likely, an already existing key material will
 * be also used in the process, so for the purpose there are further fluent methods available:
 * <ul>
 * <li>{@link DidLogDeactivatorStrategy.DidLogDeactivatorStrategyBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} for setting a signing (Ed25519) key</li>
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
 *         String initialDidLogEntryWithGeneratedKeys = null;
 *         String deactivatedDidLogEntry = null;
 *         try {
 *             URL identifierRegistryUrl = URL.of(new URI("https://127.0.0.1:54858/123456789/123456789/did.jsonl"), null);
 *             var verificationMethodKeyProvider = new Ed25519VerificationMethodKeyProviderImpl(new File("src/test/data/private.pem"), new File("src/test/data/public.pem"));
 *
 *             // NOTE that all verification material will be generated here as well
 *             initialDidLogEntryWithGeneratedKeys = WebVerifiableHistoryCreator.builder()
 *                 .verificationMethodKeyProvider(verificationMethodKeyProvider)
 *                 .build()
 *                 .create(identifierRegistryUrl);
 *
 *             // Now deactivate the previously generated initial single-entry DID log
 *             deactivatedDidLogEntry = DidLogDeactivatorStrategy.builder()
 *                      .didMethod(DidMethodEnum.detectDidMethod(initialDidLogEntryWithGeneratedKeys))
 *                      .verificationMethodKeyProvider(verificationMethodKeyProvider) // the same used during creation
 *                      .build()
 *                      .deactivate(initialDidLogEntryWithGeneratedKeys);
 *
 *         } catch (Exception e) {
 *             // some exc. handling goes here
 *             System.exit(1);
 *         }
 *
 *         // do something with the initialDidLogEntryWithGeneratedKeys/deactivatedDidLogEntry vars here
 *     }
 * }
 * </pre>
 */
@Builder
public class DidLogDeactivatorStrategy {

    @Builder.Default
    private VerificationMethodKeyProvider verificationMethodKeyProvider = new Ed25519VerificationMethodKeyProviderImpl();

    @Builder.Default
    private DidMethodEnum didMethod = DidMethodEnum.WEBVH_1_0;

    /**
     * Immediately deactivates a presumably valid DID log.
     *
     * @param didLog to deactivate. Expected to be resolvable/verifiable already.
     * @return a whole new DID log entry to be appended to the existing {@code didLog}
     * @throws DidLogDeactivatorStrategyException if deactivation fails for whatever reason.
     * @see #deactivate(String, ZonedDateTime)
     */
    public String deactivate(String didLog) throws DidLogDeactivatorStrategyException {
        return deactivate(didLog, ZonedDateTime.now());
    }

    /**
     * The file-system-as-input variation of {@link #deactivate(String)}
     *
     * @throws DidLogDeactivatorStrategyException if deactivation fails for whatever reason
     * @throws IOException                        if an I/ O error occurs reading from the file or a malformed or unmappable byte sequence is read
     * @see #deactivate(String, ZonedDateTime)
     */
    public String deactivate(File didLogFile) throws DidLogDeactivatorStrategyException, IOException {
        return deactivate(Files.readString(didLogFile.toPath()), ZonedDateTime.now());
    }

    /**
     * Deactivates a DID log for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <p>
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param didLog to deactivate. Expected to be resolvable/verifiable already.
     * @param zdt    a date-time with a time-zone in the ISO-8601 calendar system
     * @return a whole new  DID log entry to be appended to the existing {@code didLog}
     * @throws DidLogDeactivatorStrategyException if deactivation fails for whatever reason.
     */
    public String deactivate(String didLog, ZonedDateTime zdt) throws DidLogDeactivatorStrategyException {
        switch (this.didMethod) {
            case TDW_0_3 -> {
                try {
                    return TdwDeactivator.builder()
                            .verificationMethodKeyProvider(this.verificationMethodKeyProvider)
                            .build()
                            .deactivate(didLog, zdt);
                } catch (Exception e) {
                    throw new DidLogDeactivatorStrategyException(e);
                }
            }
            case WEBVH_1_0 -> {
                try {
                    return WebVerifiableHistoryDeactivator.builder()
                            .verificationMethodKeyProvider(this.verificationMethodKeyProvider)
                            .build()
                            .deactivate(didLog, zdt);
                } catch (Exception e) {
                    throw new DidLogDeactivatorStrategyException(e);
                }
            }
            default -> throw new DidLogDeactivatorStrategyException("The supplied DID log features an unsupported DID method");
        }
    }
}