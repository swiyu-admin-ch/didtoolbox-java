package ch.admin.bj.swiyu.didtoolbox.did.new_did;

import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
import ch.admin.eid.did_sidekicks.DidDocExtended;
import ch.admin.eid.did_sidekicks.DidMethodParameter;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.JcsSha256Hasher;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.Setter;

import java.net.URL;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class WebVerifiableHistory {
    protected static final String SCID_PLACEHOLDER = "{SCID}";

    // Common DID Log attributes
    protected static final String DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID = "versionId";
    protected static final String DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME = "versionTime";
    protected static final String DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS = "parameters";
    protected static final String DID_LOG_ENTRY_JSON_PROPERTY_STATE = "state";
    protected static final String DID_LOG_ENTRY_JSON_PROPERTY_PROOF = "proof";

    private final DidDocumentBuilder didDocumentBuilder;

    @Setter
    private Optional<Set<String>> updateKeys = Optional.empty();
    @Setter
    private Optional<Set<String>> nextKeyHashes = Optional.empty();
    @Setter
    private boolean isDeactivated = false;
    @Setter
    private Optional<Integer> ttl = Optional.empty();

    public WebVerifiableHistory(DidDocumentBuilder didDocumentBuilder) {
        this.didDocumentBuilder = didDocumentBuilder;
    }

    // builds initial entry
    public String build(ZonedDateTime zdt, VcDataIntegrityCryptographicSuite cryptographicSuite, URL identifierRegistryUrl) throws WebVerifiableHistoryException, VcDataIntegrityCryptographicSuiteException {
        var didLogEntryJson = new JsonObject();
        // set version ID
        didLogEntryJson.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, SCID_PLACEHOLDER);
        // set version time
        didLogEntryJson.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME, DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));
        // set parameters
        didLogEntryJson.add(DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS, this.buildMethodParameters(true));
        // set state
        didLogEntryJson.add(DID_LOG_ENTRY_JSON_PROPERTY_STATE, this.didDocumentBuilder.build(DidMethodEnum.WEBVH_1_0, identifierRegistryUrl));

        // Generate SCID and replace placeholder in did doc
        String scid = buildSCID(didLogEntryJson);
        didLogEntryJson = JsonParser.parseString(
                didLogEntryJson.toString().replace(SCID_PLACEHOLDER, scid)
        ).getAsJsonObject();

        // Set version ID
        String entryHash = "1-" + buildSCID(didLogEntryJson);
        didLogEntryJson.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, entryHash);

        // set proof
        var proofs = new JsonArray();
        proofs.add(cryptographicSuite.buildDataIntegrityProof(didLogEntryJson, null, VcDataIntegrityCryptographicSuite.PROOF_PURPOSE_ASSERTION_METHOD, zdt));
        didLogEntryJson.add(DID_LOG_ENTRY_JSON_PROPERTY_PROOF, proofs);

        return didLogEntryJson.toString();
    }

    // builds following entries
    public String build(ZonedDateTime zdt, VcDataIntegrityCryptographicSuite cryptographicSuite, String didLog) throws WebVerifiableHistoryException, VcDataIntegrityCryptographicSuiteException {
        try {
            var didLogJson = JsonParser.parseString(didLog.lines().reduce((first, second) -> second).get()).getAsJsonObject();
            var did = didLogJson.get(DID_LOG_ENTRY_JSON_PROPERTY_STATE).getAsJsonObject().get("id").getAsString();
            var versionId = didLogJson.get(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID).getAsString();
            var versionNumber = Integer.parseInt(versionId.split("-")[0]);

            var didLogEntryJson = new JsonObject();
            // set version ID
            didLogEntryJson.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, versionId); // TODO replace with old version id
            // set version time
            didLogEntryJson.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME, DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));
            // set parameters
            didLogEntryJson.add(DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS, this.buildMethodParameters(false));
            // set state
            didLogEntryJson.add(DID_LOG_ENTRY_JSON_PROPERTY_STATE, this.didDocumentBuilder.build(did));

            // Generate SCID and replace placeholder in did doc
            String scid = buildSCID(didLogEntryJson);
            didLogEntryJson = JsonParser.parseString(
                    didLogEntryJson.toString().replace(SCID_PLACEHOLDER, scid)
            ).getAsJsonObject();

            // Set version ID
            String entryHash = "%d-%s".formatted(versionNumber + 1, scid);
            didLogEntryJson.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, entryHash);

            // set proof
            var proofs = new JsonArray();
            proofs.add(cryptographicSuite.buildDataIntegrityProof(didLogEntryJson, null, VcDataIntegrityCryptographicSuite.PROOF_PURPOSE_ASSERTION_METHOD, zdt));
            didLogEntryJson.add(DID_LOG_ENTRY_JSON_PROPERTY_PROOF, proofs);

            return didLogEntryJson.toString();
        } catch (IllegalStateException e) {
            throw new WebVerifiableHistoryException("Provided DID Log is not a valid WEBVH log", e);
        }
    }

    public JsonObject buildMethodParameters(boolean isInitialEntry) {
        var parameters = new JsonObject();
        if (isInitialEntry) {
            parameters.addProperty("method", DidMethodEnum.WEBVH_1_0.toString());
            parameters.addProperty("scid", SCID_PLACEHOLDER);
            parameters.addProperty("portable", false);
        }

        if (this.isDeactivated) {
            parameters.addProperty("deactivated", true);
        }

        if (this.nextKeyHashes.isPresent()) {
            var updateKeys = new JsonArray();
            this.nextKeyHashes.get().forEach(updateKeys::add);
            parameters.add("nextKeyHashes", updateKeys);
        }

        if (this.ttl.isPresent()) {
            parameters.addProperty("ttl", this.ttl.get());
        }

        if (this.updateKeys.isPresent()) {
            var updateKeys = new JsonArray();
            this.updateKeys.get().forEach(updateKeys::add);
            parameters.add("updateKeys", updateKeys);
        }

        return parameters;
    }

    public static DidDocExtended resolveLog(String didLog) throws WebVerifiableHistoryException {
        try {
            var didLogJson = JsonParser.parseString(didLog.lines().reduce((first, second) -> second).get()).getAsJsonObject();
            var didId = didLogJson.get(DID_LOG_ENTRY_JSON_PROPERTY_STATE).getAsJsonObject().get("id").getAsString();
            var did = new Did(didId);
            return did.resolveAll(didLog);
        } catch (IllegalStateException e) {
            throw new WebVerifiableHistoryException("Provided DID Log is not a valid WEBVH DID log", e);
        } catch (DidResolveException e) {
            throw new WebVerifiableHistoryException("Failed to resolve provided DID Log", e);
        }
    }

    public static boolean isKeyRotationActive(Map<String, DidMethodParameter> parameters) {
        var nextKeyHashesParameter = parameters.get("nextKeyHashes");
        return (nextKeyHashesParameter.isArray() && !nextKeyHashesParameter.isEmptyArray());
    }

    // Expects a did log without proof
    private String buildSCID(JsonObject didLog) throws WebVerifiableHistoryException {
        try (var hasher = JcsSha256Hasher.Companion.build()) {
            return hasher.base58btcEncodeMultihash(didLog.toString());
        } catch (DidSidekicksException e) {
            throw new WebVerifiableHistoryException("Failed to hash json", e);
        }
    }
}
