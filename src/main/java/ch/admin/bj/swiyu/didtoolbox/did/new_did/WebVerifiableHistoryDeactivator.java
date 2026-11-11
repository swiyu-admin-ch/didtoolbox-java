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

@Builder
public class WebVerifiableHistoryDeactivator {

    /**
     * Constructs a builder for deactivating did webvh logs with the provided crypto Suite
     *
     * @param suite used to create the log entry signature
     * @return the builder, it's recommended to also call 'assertionMethods' or 'authentications' on it.
     */
    public static WebVerifiableHistoryDeactivator.WebVerifiableHistoryDeactivatorBuilder builder(@NonNull VcDataIntegrityCryptographicSuite suite) {
        return new WebVerifiableHistoryDeactivator.WebVerifiableHistoryDeactivatorBuilder().cryptographicSuite(suite);
    }

    /**
     * Handles creation of the vc data integrity proof.
     */
    private VcDataIntegrityCryptographicSuite cryptographicSuite;

    @Builder.Default
    private Set<UpdateKeysDidMethodParameter> updateKeys = Set.of();

    public String deactivateDidLog(String didLog, ZonedDateTime zdt) throws WebVerifiableHistoryException, VcDataIntegrityCryptographicSuiteException, InterruptedException {
        var builder = new WebVerifiableHistory(new DidDocumentBuilder());

        var did = WebVerifiableHistory.resolveLog(didLog);

        var prefix = "";
        if (WebVerifiableHistory.isKeyRotationActive(did.getDidMethodParameters())) {
            if (this.updateKeys.isEmpty()) {
                throw new WebVerifiableHistoryException("Key pre-rotation is currently active, but no new update keys have been provided.");
            }

            var updater = WebVerifiableHistoryUpdater.builder(this.cryptographicSuite, new DidDocumentBuilder())
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
        return prefix + builder.build(zdt, this.cryptographicSuite, didLog);
    }
}
