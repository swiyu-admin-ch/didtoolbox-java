package ch.admin.bj.swiyu.didtoolbox.did.new_did;

import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import lombok.Builder;
import lombok.NonNull;

import java.net.URL;
import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Builder
public class WebVerifiableHistoryCreator {

    /**
     * Constructs a builder for creating did webvh logs with the provided crypto Suite
     *
     * @param suite used to create the log entry signature
     * @return the builder, it's recommended to also call 'assertionMethods' or 'authentications' on it.
     */
    public static WebVerifiableHistoryCreatorBuilder builder(@NonNull VcDataIntegrityCryptographicSuite suite, DidDocumentBuilder documentBuilder) {
        return new WebVerifiableHistoryCreatorBuilder().cryptographicSuite(suite).didDocumentBuilder(documentBuilder);
    }

    /**
     * Handles creation of the vc data integrity proof.
     */
    private VcDataIntegrityCryptographicSuite cryptographicSuite;

    /**
     * Builds the document to be included in the log entry.
     */
    private DidDocumentBuilder didDocumentBuilder;

    @Builder.Default
    private Set<UpdateKeysDidMethodParameter> updateKeys = Set.of();

    @Builder.Default
    private Set<UpdateKeysDidMethodParameter> nextKeyHashes = Set.of();

    public String createDidLog(URL identifierRegistryUrl, ZonedDateTime zdt) throws DidLogCreatorStrategyException, VcDataIntegrityCryptographicSuiteException {
        var builder = new WebVerifiableHistory(this.didDocumentBuilder);

        var updateKeys = new HashSet<String>();
        updateKeys.add(cryptographicSuite.getVerificationKeyMultibase());
        this.updateKeys.forEach(key -> updateKeys.add(key.getUpdateKey()));
        builder.setUpdateKeys(Optional.of(updateKeys));

        if (!this.nextKeyHashes.isEmpty()) {
            var nextKeyHashes = this.nextKeyHashes.stream().map(key ->
                NextKeyHashesDidMethodParameter.of(key.getUpdateKey()).getNextKeyHash()
            ).collect(Collectors.toSet());
            builder.setNextKeyHashes(Optional.of(nextKeyHashes));
        }

        return builder.build(zdt, this.cryptographicSuite, identifierRegistryUrl);
    }
}
