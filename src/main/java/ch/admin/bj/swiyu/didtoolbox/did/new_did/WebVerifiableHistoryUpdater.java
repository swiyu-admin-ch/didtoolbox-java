package ch.admin.bj.swiyu.didtoolbox.did.new_did;

import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import com.google.gson.JsonParser;
import lombok.Builder;
import lombok.NonNull;

import java.net.URL;
import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Builder
public class WebVerifiableHistoryUpdater {

    /**
     * Constructs a builder for creating did webvh logs with the provided crypto Suite
     *
     * @param suite used to create the log entry signature
     * @return the builder, it's recommended to also call 'assertionMethods' or 'authentications' on it.
     */
    public static WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder builder(@NonNull VcDataIntegrityCryptographicSuite suite, DidDocumentBuilder documentBuilder) {
        return new WebVerifiableHistoryUpdater.WebVerifiableHistoryUpdaterBuilder().cryptographicSuite(suite).didDocumentBuilder(documentBuilder);
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
    private Set<NextKeyHashesDidMethodParameter> nextKeyHashes = Set.of();

    public String updateDidLog(String didLog, ZonedDateTime zdt) throws DidLogCreatorStrategyException, VcDataIntegrityCryptographicSuiteException, DidResolveException {
        var builder = new WebVerifiableHistory(this.didDocumentBuilder);

        /*
        var updateKeys = new HashSet<String>();
        updateKeys.add(cryptographicSuite.getVerificationKeyMultibase());
        this.updateKeys.forEach(key -> updateKeys.add(key.getUpdateKey()));
        builder.setUpdateKeys(Optional.of(updateKeys));
         */

        if (!this.nextKeyHashes.isEmpty()) {
            var nextKeyHashes = this.nextKeyHashes.stream().map(NextKeyHashesDidMethodParameter::getNextKeyHash).collect(Collectors.toSet());
            builder.setNextKeyHashes(Optional.of(nextKeyHashes));
        } else {
            // check if empty list needs to be added, e.g. key rotation active
        }

        // TODO set next key hashes, must be set to empty list if current entry (before update) has next key hashes.

        if (!this.nextKeyHashes.isEmpty()) {
            var nextKeyHashes = this.nextKeyHashes.stream().map(NextKeyHashesDidMethodParameter::getNextKeyHash).collect(Collectors.toSet());
            builder.setNextKeyHashes(Optional.of(nextKeyHashes));
        }

        return builder.build(zdt, this.cryptographicSuite, didLog);
    }
}
