package ch.admin.bj.swiyu.didtoolbox.did.new_did;

import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import lombok.Builder;
import lombok.NonNull;

import java.net.URL;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * {@link WebVerifiableHistoryCreator} implements
 * <a href="https://identity.foundation/didwebvh/v1.0/#create-register">did:webvh create</a>
 * and generates a new DID log.
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@code builder()} method.
 * <p>
 * Once a {@link WebVerifiableHistoryCreator} object is initialized
 * a <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>
 * log can be created by calling {@link #createDidLog(URL)} method.
 */
@Builder
public class WebVerifiableHistoryCreator {

    /**
     * Constructs a builder for creating DID WEBVH logs with the provided crypto Suite and DID document
     *
     * @param suite used to create the log entry signature
     * @return the builder, it's recommended to also call 'assertionMethods' or 'authentications' on it.
     */
    public static WebVerifiableHistoryCreatorBuilder builder( DidDocumentBuilder documentBuilder, @NonNull VcDataIntegrityCryptographicSuite suite) {
        return new WebVerifiableHistoryCreatorBuilder().cryptographicSuite(suite).didDocumentBuilder(documentBuilder);
    }
    // Class definition for Javadoc to reference
    public static class WebVerifiableHistoryCreatorBuilder {}

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
    private Set<UpdateKeysDidMethodParameter> nextKeyHashes = Set.of();

    /**
     * Creates the DID log.
     *
     * @param identifierRegistryUrl
     * @return a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log
     * @throws WebVerifiableHistoryException
     * @throws VcDataIntegrityCryptographicSuiteException
     */
    public String createDidLog(URL identifierRegistryUrl) throws WebVerifiableHistoryException, VcDataIntegrityCryptographicSuiteException {
        return this.createDidLog(identifierRegistryUrl, ZonedDateTime.now());
    }

    /**
     * Creates the DID log.
     *
     * @param identifierRegistryUrl
     * @param zdt timestamp of log entry creation
     * @return a valid <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log
     * @throws WebVerifiableHistoryException
     * @throws VcDataIntegrityCryptographicSuiteException
     */
    public String createDidLog(URL identifierRegistryUrl, ZonedDateTime zdt) throws WebVerifiableHistoryException, VcDataIntegrityCryptographicSuiteException {
        var builder = new WebVerifiableHistory(this.didDocumentBuilder);

        var updateKeys = new HashSet<String>();
        updateKeys.add(this.cryptographicSuite.getVerificationKeyMultibase());
        this.updateKeys.forEach(key -> updateKeys.add(key.getUpdateKey()));
        builder.setUpdateKeys(Optional.of(updateKeys));

        if (!this.nextKeyHashes.isEmpty()) {
            var nextKeyHashes = this.nextKeyHashes.stream().map(key ->
                NextKeyHashesDidMethodParameter.of(key.getUpdateKey()).getNextKeyHash()
            ).collect(Collectors.toSet());
            builder.setNextKeyHashes(Optional.of(nextKeyHashes));
        }

        return builder.buildInitial(identifierRegistryUrl, zdt, this.cryptographicSuite);
    }
}