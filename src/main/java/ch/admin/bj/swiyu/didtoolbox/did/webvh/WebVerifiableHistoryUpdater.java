package ch.admin.bj.swiyu.didtoolbox.did.webvh;

import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.DidDocumentBuilder;
import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import ch.admin.eid.did_sidekicks.DidMethodParameter;
import lombok.Builder;

import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * {@link WebVerifiableHistoryUpdater} implements
 * <a href="https://identity.foundation/didwebvh/v1.0/#update-rotate">did:webvh update</a>
 * and generates a new DID log entry, to be appended to the log.
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@code builder()} method.
 * <p>
 * Once a {@link WebVerifiableHistoryUpdater} object is initialized
 * a <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>
 * log can be created by calling {@link #updateDidLog(String)} method.
 * <pre>
 * {@code
 *     import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
 *     import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
 *     import ch.admin.bj.swiyu.didtoolbox.did.new_did.DidDocumentBuilder;
 *     import ch.admin.bj.swiyu.didtoolbox.did.new_did.WebVerifiableHistoryCreator;
 *     import ch.admin.bj.swiyu.didtoolbox.did.new_did.WebVerifiableHistoryException;
 *     import ch.admin.bj.swiyu.didtoolbox.did.new_did.WebVerifiableHistoryUpdater;
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
 *     var updater = WebVerifiableHistoryUpdater.builder(new DidDocumentBuilder(), cryptoSuite).build();
 *     var updatedDidLog = initialDidLog + System.lineSeparator() + updater.updateDidLog(initialDidLog);
 * }
 * </pre>
 */
@Builder
public class WebVerifiableHistoryUpdater {

    /**
     * Constructs a builder for updating did webvh logs with the provided crypto Suite
     *
     * @param suite used to create the log entry signature
     * @return the builder, it's recommended to also call 'assertionMethods' or 'authentications' on it.
     */
    public static WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder builder(DidDocumentBuilder documentBuilder, VcDataIntegrityCryptographicSuite suite) {
        return new WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder().cryptographicSuite(suite).didDocumentBuilder(documentBuilder);
    }
    // Class definition for Javadoc to reference
    public static class WebVerifiableHistoryUpdaterBuilder {}

    /**
     * Handles creation of the vc data integrity proof.
     */
    private VcDataIntegrityCryptographicSuite cryptographicSuite;

    /**
     * Builds the document to be included in the log entry.
     */
    private DidDocumentBuilder didDocumentBuilder;

    /**
     * Sets the [updateKeys] <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">DID method parameters</a>.
     * They specify which keys can be used for the data verification proof of the log.
     */
    @Builder.Default
    private Set<UpdateKeysDidMethodParameter> updateKeys = Set.of();

    /**
     * Sets the [nextKeyHashes] <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">DID method parameters</a>.
     * They are the hashes of the update keys allowed for the verification proof generation of the next log entry
     */
    @Builder.Default
    private Set<NextKeyHashesDidMethodParameter> nextKeyHashes = Set.of();

    /**
     * Specifies the DID WEBVH version to use.
     */
    @Builder.Default
    private DidMethodEnum didMethod = DidMethodEnum.WEBVH_1_0;

    /**
     * Creates the new DID log entry.
     *
     * @param didLog the DID log to update
     * @return a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log entry, to be appended to the DID log.
     * @throws WebVerifiableHistoryException
     * @throws VcDataIntegrityCryptographicSuiteException
     */
    public String updateDidLog(String didLog) throws WebVerifiableHistoryException, VcDataIntegrityCryptographicSuiteException {
        return this.updateDidLog(didLog, ZonedDateTime.now());
    }

    /**
     * Creates the new DID log entry.
     *
     * @param didLog the DID log to update
     * @param zdt timestamp of log entry creation
     * @return a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log entry, to be appended to the DID log.
     * @throws WebVerifiableHistoryException
     * @throws VcDataIntegrityCryptographicSuiteException
     */
    public String updateDidLog(String didLog, ZonedDateTime zdt) throws WebVerifiableHistoryException, VcDataIntegrityCryptographicSuiteException {
        var builder = new WebVerifiableHistory(this.didDocumentBuilder);

        var did = WebVerifiableHistory.resolveLog(didLog);
        var parameters = did.getDidMethodParameters();

        var isKeyPrerotationActive = WebVerifiableHistory.isKeyRotationActive (parameters);
        checkKeys(isKeyPrerotationActive, parameters);

        if (!this.nextKeyHashes.isEmpty()) {
            var nextKeyHashes = this.nextKeyHashes.stream().map(NextKeyHashesDidMethodParameter::getNextKeyHash).collect(Collectors.toSet());
            builder.setNextKeyHashes(Optional.of(nextKeyHashes));
        } else if (isKeyPrerotationActive) {
            // Empty set to disable key pre-rotation
            builder.setNextKeyHashes(Optional.of(Set.of()));
        }

        if (!this.updateKeys.isEmpty()) {
            var updateKeys = this.updateKeys.stream().map(UpdateKeysDidMethodParameter::getUpdateKey).collect(Collectors.toSet());
            builder.setUpdateKeys(Optional.of(updateKeys));
        } else if (isKeyPrerotationActive) {
            throw new WebVerifiableHistoryException("Key pre-rotation is currently active, but no new update keys have been provided.");
        }

        return builder.build(didMethod, didLog, zdt, this.cryptographicSuite);
    }

    /**
     * Checks if the set keys are valid for the update entry.
     *
     * @param isKeyRotationActive
     * @param parameters
     * @throws WebVerifiableHistoryException
     */
    private void checkKeys(boolean isKeyRotationActive, Map<String, DidMethodParameter> parameters) throws WebVerifiableHistoryException {
        if (this.nextKeyHashes.isEmpty() && !isKeyRotationActive) {
            return;
        }

        var currentUpdateKeys = parameters.get("updateKeys").getStringArrayValue().stream().map(s -> NextKeyHashesDidMethodParameter.of(s).getNextKeyHash()).collect(Collectors.toSet());
        for (var nextKeyHash : this.nextKeyHashes) {
            if (currentUpdateKeys.contains(nextKeyHash)) {
                throw new WebVerifiableHistoryException("Rotating to currently used update key is not allowed.");
            }
        }
    }
}
