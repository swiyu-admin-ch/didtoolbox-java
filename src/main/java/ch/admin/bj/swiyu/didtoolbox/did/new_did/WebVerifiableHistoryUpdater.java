package ch.admin.bj.swiyu.didtoolbox.did.new_did;

import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.model.NamedDidMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameter;
import ch.admin.eid.did_sidekicks.DidMethodParameter;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import com.google.gson.JsonParser;
import lombok.Builder;
import lombok.NonNull;

import java.net.URL;
import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.didtoolbox.did.new_did.WebVerifiableHistory.DID_LOG_ENTRY_JSON_PROPERTY_STATE;

@Builder
public class WebVerifiableHistoryUpdater {

    /**
     * Constructs a builder for updating did webvh logs with the provided crypto Suite
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

        return builder.build(zdt, this.cryptographicSuite, didLog);
    }

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
