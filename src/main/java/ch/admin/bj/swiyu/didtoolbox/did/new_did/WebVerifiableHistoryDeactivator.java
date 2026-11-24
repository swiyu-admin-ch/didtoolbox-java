package ch.admin.bj.swiyu.didtoolbox.did.new_did;

import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
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
     * Sets the [updateKeys] <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">DID method parameters</a>.
     * They specify which keys can be used for the data verification proof of the log.
     */
    @Builder.Default
    private Set<UpdateKeysDidMethodParameter> updateKeys = Set.of();

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
            if (this.updateKeys.isEmpty()) {
                throw new WebVerifiableHistoryException("Key pre-rotation is currently active, but no new update keys have been provided.");
            }

            var updater = WebVerifiableHistoryUpdater.builder(new DidDocumentBuilder(), this.cryptographicSuite)
                    .updateKeys(this.updateKeys)
                    .build();

            prefix += updater.updateDidLog(didLog,zdt);
            didLog += prefix;
            prefix += System.lineSeparator();

            zdt.plusSeconds(1);
            Thread.sleep(Duration.ofSeconds(1));
        }

        builder.setUpdateKeys(Optional.of(Set.of()));
        builder.setDeactivated(true);
        return prefix + builder.build(didLog, zdt, this.cryptographicSuite);
    }
}
