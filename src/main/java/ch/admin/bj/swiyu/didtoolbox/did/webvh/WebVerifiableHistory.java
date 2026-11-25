package ch.admin.bj.swiyu.didtoolbox.did.webvh;

import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.DidDocumentBuilder;
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

/**
 * {@link WebVerifiableHistory} is  in charge of
 * <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a> log generation.
 * <p>
 * It also provides helpers to for the construction of new DID WEBVH logs.
 * <p>
 * Once a {@link WebVerifiableHistory} object is initialized
 * a <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>
 * log can be created by calling the {@link #buildInitial(DidMethodEnum, URL, ZonedDateTime, VcDataIntegrityCryptographicSuite)}
 * or {@link #build(DidMethodEnum, String, ZonedDateTime, VcDataIntegrityCryptographicSuite)} method.
 */
public class WebVerifiableHistory {
    protected static final String SCID_PLACEHOLDER = "{SCID}";

    // Common DID Log attributes
    protected static final String DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID = "versionId";
    protected static final String DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME = "versionTime";
    protected static final String DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS = "parameters";
    protected static final String DID_LOG_ENTRY_JSON_PROPERTY_STATE = "state";
    protected static final String DID_LOG_ENTRY_JSON_PROPERTY_PROOF = "proof";

    private final DidDocumentBuilder didDocumentBuilder;

    /**
     * Sets the [updateKeys] <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">DID method parameters</a>.
     * They specify which keys can be used for the data verification proof of the log.
     */
    @Setter
    private Optional<Set<String>> updateKeys = Optional.empty();

    /**
     * Sets the [nextKeyHashes] <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">DID method parameters</a>.
     * They are the hashes of the update keys allowed for the verification proof generation of the next log entry
     */
    @Setter
    private Optional<Set<String>> nextKeyHashes = Optional.empty();

    /**
     * Sets the [deactivated] <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">DID method parameters</a>.
     * Specifies if the document is deactivated, allowing no more updates to the DID log.
     */
    @Setter
    private boolean isDeactivated = false;

    /**
     * Sets the [ttl] <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">DID method parameters</a>.
     * Specifies how long the DID log should be cached.
     */
    @Setter
    private Optional<Integer> ttl = Optional.empty();

    /**
     * Instantiates a new DID WEBVH log creator.
     *
     * @param didDocumentBuilder builder for the document of the log entry.
     */
    public WebVerifiableHistory(DidDocumentBuilder didDocumentBuilder) {
        this.didDocumentBuilder = didDocumentBuilder;
    }

    /**
     * Builds a new initial log entry, based on the provided URL.
     *
     * @param identifierRegistryUrl
     * @param zdt
     * @param cryptographicSuite
     * @return The created DID WEBVH log
     * @throws WebVerifiableHistoryException
     * @throws VcDataIntegrityCryptographicSuiteException
     */
    public String buildInitial(DidMethodEnum method, URL identifierRegistryUrl, ZonedDateTime zdt, VcDataIntegrityCryptographicSuite cryptographicSuite) throws WebVerifiableHistoryException, VcDataIntegrityCryptographicSuiteException {
        var didLogEntryJson = new JsonObject();
        // set version ID
        didLogEntryJson.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, SCID_PLACEHOLDER);
        // set version time
        didLogEntryJson.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME, DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));
        // set parameters
        didLogEntryJson.add(DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS, this.buildMethodParameters(method, true));
        // set state
        didLogEntryJson.add(
                DID_LOG_ENTRY_JSON_PROPERTY_STATE,
                this.didDocumentBuilder.build(buildInitialDid(method, identifierRegistryUrl)));

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

    /**
     * Builds a new log entry to be appended to the provided DID log.
     *
     * @param didLog
     * @param zdt
     * @param cryptographicSuite
     * @return the new DID log entry, previous entries are not included
     * @throws WebVerifiableHistoryException
     * @throws VcDataIntegrityCryptographicSuiteException
     */
    public String build(DidMethodEnum method, String didLog, ZonedDateTime zdt, VcDataIntegrityCryptographicSuite cryptographicSuite) throws WebVerifiableHistoryException, VcDataIntegrityCryptographicSuiteException {
        try {
            var didLogJson = JsonParser.parseString(didLog.lines().reduce((first, second) -> second).get()).getAsJsonObject();
            var did = didLogJson.get(DID_LOG_ENTRY_JSON_PROPERTY_STATE).getAsJsonObject().get("id").getAsString();
            var versionId = didLogJson.get(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID).getAsString();
            var versionNumber = Integer.parseInt(versionId.split("-")[0]);

            var didLogEntryJson = new JsonObject();
            // set old version ID, to be replaced later, used for entry hash generation
            didLogEntryJson.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, versionId);
            // set version time
            didLogEntryJson.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME, DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));
            // set parameters
            didLogEntryJson.add(DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS, this.buildMethodParameters(method, false));
            // set state
            didLogEntryJson.add(DID_LOG_ENTRY_JSON_PROPERTY_STATE, this.didDocumentBuilder.build(did));

            // Generate entryHash (same logic as SCID) and replace placeholder in did doc
            String entryHash = buildSCID(didLogEntryJson);
            didLogEntryJson = JsonParser.parseString(
                    didLogEntryJson.toString().replace(SCID_PLACEHOLDER, entryHash)
            ).getAsJsonObject();

            // Set actual version ID
            didLogEntryJson.addProperty(DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID, "%d-%s".formatted(versionNumber + 1, entryHash));

            // set proof
            var proofs = new JsonArray();
            proofs.add(cryptographicSuite.buildDataIntegrityProof(didLogEntryJson, null, VcDataIntegrityCryptographicSuite.PROOF_PURPOSE_ASSERTION_METHOD, zdt));
            didLogEntryJson.add(DID_LOG_ENTRY_JSON_PROPERTY_PROOF, proofs);

            return didLogEntryJson.toString();
        } catch (IllegalStateException e) {
            throw new WebVerifiableHistoryException("Provided DID Log is not a valid WEBVH log", e);
        }
    }

    /**
     * Builds the <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">method parameters</a>
     * of the DID log.
     *
     * @param method specifies the DID WEBVH version
     * @param isInitialEntry used to include entries only specified in the initial entry
     * @return
     */
    protected JsonObject buildMethodParameters(DidMethodEnum method, boolean isInitialEntry) {
        var parameters = new JsonObject();
        if (isInitialEntry) {
            parameters.addProperty("method", method.toString());
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

    /**
     * Resolves the didLog, executing the <a href="https://identity.foundation/didwebvh/v1.0/#read-resolve">read</a>
     * DID method operation.
     *
     * @param didLog
     * @return
     * @throws WebVerifiableHistoryException
     */
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

    /**
     * Checks if the <a href="https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification">key pre-rotation</a>
     * is active.
     *
     * @param parameters
     * @return
     */
    public static boolean isKeyRotationActive(Map<String, DidMethodParameter> parameters) {
        var nextKeyHashesParameter = parameters.get("nextKeyHashes");
        return (nextKeyHashesParameter.isArray() && !nextKeyHashesParameter.isEmptyArray());
    }

    /**
     * Generates the <a href="https://identity.foundation/didwebvh/v1.0/#scid-generation-and-verification">SCID</a>.
     * Note that NO modifications are done to the didLog and MUST be done by the caller.
     *
     * @param didLog
     * @return
     * @throws WebVerifiableHistoryException
     */
    private String buildSCID(JsonObject didLog) throws WebVerifiableHistoryException {
        try (var hasher = JcsSha256Hasher.Companion.build()) {
            return hasher.base58btcEncodeMultihash(didLog.toString());
        } catch (DidSidekicksException e) {
            throw new WebVerifiableHistoryException("Failed to hash json", e);
        }
    }

    /**
     * Constructs the DID based on the provided URL.
     *
     * @param method specifies the version of the did method
     * @param identifierRegistryUrl
     * @return
     */
    private String buildInitialDid(DidMethodEnum method, URL identifierRegistryUrl) {
        var did = "%s:{SCID}:%s".formatted(DidMethodEnum.WEBVH_1_0.getPrefix(), identifierRegistryUrl.getHost());
        int port = identifierRegistryUrl.getPort(); // the port number, or -1 if the port is not set
        if (port != -1) {
            did = "%s%%3A%d".formatted(did, port);
        }
        String path = identifierRegistryUrl.getPath(); // the path part of this URL, or an empty string if one does not exist
        if (!path.isEmpty()) {
            did = "%s%s".formatted(did,
                    path.replace("/did.jsonl", "") // cleanup
                            .replace("/", ":")); // w.r.t. https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation
        }
        return did;
    }
}
