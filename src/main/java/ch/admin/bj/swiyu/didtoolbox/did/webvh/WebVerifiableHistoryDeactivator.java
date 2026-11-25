package ch.admin.bj.swiyu.didtoolbox.did.webvh;

import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.DidDocumentBuilder;
import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import lombok.Builder;
import lombok.NonNull;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.Optional;
import java.util.Set;

/**
 * {@link WebVerifiableHistoryDeactivator} implements
 * <a href="https://identity.foundation/didwebvh/v1.0/#deactivate-revoke">did:webvh deactivate</a>
 * and generates a new DID log entry, to be appended to the log.
 * <p>
 * In case <a href="https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification">key pre-rotation</a>
 * is active, an additional entry is generated.
 * This is done to remove all update keys in the final entry.
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@code builder()} method.
 * <p>
 * Once a {@link WebVerifiableHistoryDeactivator} object is initialized
 * a <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>
 * log can be created by calling {@link #deactivateDidLog(String)} method.
 * <pre>
 * {@code
 *     import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
 *     import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
 *     import ch.admin.bj.swiyu.didtoolbox.did.new_did.*;
 *
 *     import java.net.MalformedURLException;
 *     import java.net.URL;
 *     import java.time.Duration;
 *
 *     var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
 *     var initialDidLog = WebVerifiableHistoryCreator.builder(new DidDocumentBuilder(), cryptoSuite).build().createDidLog(new URL("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085"));
 *
 *     // To ensure the DID log entries do NOT share the same version time.
 *     Thread.sleep(Duration.ofSeconds(1));
 *
 *     var deactivator = WebVerifiableHistoryDeactivator.builder(cryptoSuite).build();
 *     var deactivatedDidLog = initialDidLog + System.lineSeparator() + deactivator.deactivateDidLog(initialDidLog);
 *
 *     System.out.println(deactivatedDidLog);
 * }
 * </pre>
 */
@Builder
public class WebVerifiableHistoryDeactivator {

    /**
     * Constructs a builder for deactivating did webvh logs with the provided crypto suite
     *
     * @param suite used to create the log entry signature
     * @return the builder, it's recommended to also call 'assertionMethods' or 'authentications' on it.
     */
    public static WebVerifiableHistoryDeactivator.WebVerifiableHistoryDeactivatorBuilder builder(@NonNull VcDataIntegrityCryptographicSuite suite) {
        return new WebVerifiableHistoryDeactivator.WebVerifiableHistoryDeactivatorBuilder().cryptographicSuite(suite);
    }
    // Class definition for Javadoc to reference
    public static class WebVerifiableHistoryDeactivatorBuilder {}

    /**
     * Handles creation of the vc data integrity proof.
     */
    private VcDataIntegrityCryptographicSuite cryptographicSuite;

    /**
     * Specifies the DID WEBVH version to use.
     */
    @Builder.Default
    private DidMethodEnum didMethod = DidMethodEnum.WEBVH_1_0;

    /**
     * Creates the final DID log entry.
     *
     * @param didLog
     * @return a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log. In case of active key pre-rotation, 2 entries are returned.
     * @throws WebVerifiableHistoryException
     * @throws VcDataIntegrityCryptographicSuiteException
     * @throws InterruptedException if it fails to wait one second to create the 2nd entry in case of key pre-rotation.
     */
    public String deactivateDidLog(String didLog) throws WebVerifiableHistoryException, VcDataIntegrityCryptographicSuiteException, InterruptedException {
        return this.deactivateDidLog(didLog, ZonedDateTime.now());
    }

    /**
     * Creates the final DID log entry.
     *
     * @param didLog
     * @param zdt timestamp of log entry creation
     * @return a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log. In case of active key pre-rotation, 2 entries are returned.
     * @throws WebVerifiableHistoryException
     * @throws VcDataIntegrityCryptographicSuiteException
     * @throws InterruptedException if it fails to wait one second to create the 2nd entry in case of key pre-rotation.
     */
    public String deactivateDidLog(String didLog, ZonedDateTime zdt) throws WebVerifiableHistoryException, VcDataIntegrityCryptographicSuiteException, InterruptedException {
        var builder = new WebVerifiableHistory(new DidDocumentBuilder());

        var did = WebVerifiableHistory.resolveLog(didLog);

        var prefix = "";
        if (WebVerifiableHistory.isKeyRotationActive(did.getDidMethodParameters())) {
            var updater = WebVerifiableHistoryUpdater.builder(new DidDocumentBuilder(), this.cryptographicSuite)
                    .updateKeys(Set.of(UpdateKeysDidMethodParameter.of(cryptographicSuite.getVerificationKeyMultibase())))
                    .build();

            prefix += updater.updateDidLog(didLog,zdt);
            didLog += prefix;
            prefix += System.lineSeparator();

            zdt.plusSeconds(1);
            Thread.sleep(Duration.ofSeconds(1));
        }

        builder.setUpdateKeys(Optional.of(Set.of()));
        builder.setDeactivated(true);
        return prefix + builder.build(didMethod, didLog, zdt, this.cryptographicSuite);
    }
}
