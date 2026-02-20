package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.JcsSha256Hasher;
import com.google.gson.*;

import java.net.URL;
import java.util.Map;
import java.util.Set;

public abstract class AbstractDidLogEntryBuilder {

    protected final static String SCID_PLACEHOLDER = "{SCID}";

    protected final static String DID_LOG_ENTRY_JSON_PROPERTY_VERSION_ID = "versionId";
    protected final static String DID_LOG_ENTRY_JSON_PROPERTY_VERSION_TIME = "versionTime";
    protected final static String DID_LOG_ENTRY_JSON_PROPERTY_PARAMETERS = "parameters";
    protected final static String DID_LOG_ENTRY_JSON_PROPERTY_STATE = "state";

    protected DidLogMeta didLogMeta;

    protected static JsonObject buildVerificationMethodWithPublicKeyJwk(String didTDW, String keyID, String publicKeyJwk) {

        var verificationMethodObj = new JsonObject();
        verificationMethodObj.addProperty("id", didTDW + "#" + keyID);
        // CAUTION The "controller" property must not be present w.r.t.:
        // - https://confluence.bit.admin.ch/x/3e0EMw
        verificationMethodObj.addProperty("type", "JsonWebKey2020");
        // CAUTION The "publicKeyMultibase" property must not be present w.r.t.:
        // - https://confluence.bit.admin.ch/x/3e0EMw
        verificationMethodObj.add("publicKeyJwk", JsonParser.parseString(publicKeyJwk).getAsJsonObject());

        return verificationMethodObj;
    }

    /**
     * Build self-certifying identifier (SCID) - an object identifier derived from initial data such that an attacker could not
     * create a new object with the same identifier. The input for a did:webvh SCID is the initial DIDDoc with the placeholder
     * {SCID} wherever the SCID is to be placed.
     * <p>
     * Also see <a href="https://identity.foundation/didwebvh/v0.3/#generate-entry-hash">generate-entry-hash (did:tdw)</a> or
     * <a href="https://identity.foundation/didwebvh/v1.0/#generate-entry-hash">generate-entry-hash (did:tdw)</a>.
     *
     * @param didLogEntryWithoutProofAndSignature
     * @return
     * @throws DidLogCreatorStrategyException
     */
    protected static String buildSCID(JsonElement didLogEntryWithoutProofAndSignature) throws DidLogCreatorStrategyException {
        try (var hasher = JcsSha256Hasher.Companion.build()) {
            return hasher.base58btcEncodeMultihash(didLogEntryWithoutProofAndSignature.toString());
        } catch (DidSidekicksException e) {
            throw new DidLogCreatorStrategyException(e);
        }
    }

    /**
     * Setup the class members w.r.t. outcome of the supplied DID log resolution process.
     *
     * @param didLog to "peek" into
     * @throws DidLogMetaPeekerException if "peeking" failed for whatever reason
     */
    protected void peek(String didLog)
            throws DidLogMetaPeekerException {

        if (getDidMethod().isTdw03()) {
            this.didLogMeta = TdwDidLogMetaPeeker.peek(didLog);
        } else if (getDidMethod().isWebVh10()) {
            this.didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog);
        } else {
            throw new IllegalArgumentException("Unsupported DID method");
        }
    }

    /**
     * Specifies a specification version to be used for processing the DID’s log.
     * Each acceptable value in turn defines what cryptographic algorithms are permitted for the current and subsequent DID log entries.
     * <p>
     * As required by:
     * <ul>
     *   <li><a href="https://identity.foundation/didwebvh/v0.3/#didwebvh-did-method-parameters">did:tdw</a> or</li>
     *   <li><a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">did:webvh</a></li>
     * </il>
     *
     * @return name of the DID method
     */
    protected abstract DidMethodEnum getDidMethod();

    /**
     * Creates a JSON object representing DID method parameters
     * as specified by <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">did:webvh</a>
     * and taking into account all the supplied PEM files.
     *
     * @param verificationMethodKeyProvider    an implementation of {@link VerificationMethodKeyProvider} providing
     *                                         one of {@code updateKey} DID method parameter values.
     * @param updateKeysParameter              optional set of {@link NextKeyHashesDidMethodParameter} objects (supplied complementary to {@code updateKeys}),
     *                                         each featuring a multibase-encoded public key to be used for the {@code updateKeys} DID method parameter.
     *                                         Eventually, all the keys supplied one way or another are simply combined into a distinct list of values.
     * @param nextKeyHashesDidMethodParameters optional set of {@link NextKeyHashesDidMethodParameter} objects (supplied complementary to {@code nextKeys}),
     *                                         each delivering a hash (of a public key) to be used for the {@code nextKeyHashes} DID method parameter,
     *                                         as specified by <a href="https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification">pre-rotation-key-hash-generation-and-verification</a>.
     *                                         Eventually, all the keys supplied one way or another are simply combined into a distinct list of values.
     * @return a JSON object representing DID method parameters
     * @throws DidLogCreatorStrategyException if parsing any of supplied PEM files (via {@code updateKeys}/{@code nextKeys} param) fails
     */
    @SuppressWarnings({"PMD.AvoidInstantiatingObjectsInLoops", "PMD.CyclomaticComplexity", "PMD.CognitiveComplexity"})
    protected JsonObject createDidParams(VerificationMethodKeyProvider verificationMethodKeyProvider,
                                         Set<UpdateKeysDidMethodParameter> updateKeysParameter,
                                         Set<NextKeyHashesDidMethodParameter> nextKeyHashesDidMethodParameters) throws DidLogCreatorStrategyException {

        // Define the parameters (https://identity.foundation/didwebvh/v1.0/#didtdw-did-method-parameters)
        // The third item in the input JSON array MUST be the parameters JSON object.
        // The parameters are used to configure the DID generation and verification processes.
        // All parameters MUST be valid and all required values in the first version of the DID MUST be present.
        JsonObject didMethodParameters = new JsonObject();
        didMethodParameters.addProperty("method", getDidMethod().asString());
        didMethodParameters.addProperty("scid", SCID_PLACEHOLDER);

        /*
        Generate the authorization key pair(s) Authorized keys are authorized to control (create, update, deactivate) the DID.
        This includes generating any other key pairs that will be placed into the initial DIDDoc for the DID.

        For each authorization key pair, generate a multikey based on the key pair’s public key.
        The multikey representations of the public keys are placed in the updateKeys item in parameters.

        updateKeys: A list of one or more multikey formatted public keys associated with the private keys that are
        authorized to sign the log entries that update the DID from one version to the next. An instance of the list in
        an entry replaces the previously active list. If an entry does not have the updateKeys item,
        the currently active list continues to apply.
         */
        var updateKeysJsonArray = new JsonArray();

        updateKeysJsonArray.add(verificationMethodKeyProvider.getVerificationKeyMultibase()); // first and foremost...

        if (updateKeysParameter != null) {
            for (var param : updateKeysParameter) { // ...and then add the rest, if any

                var updateKey = param.getUpdateKey();

                if (!updateKeysJsonArray.contains(new JsonPrimitive(updateKey))) { // it is a distinct list of keys, after all
                    updateKeysJsonArray.add(updateKey);
                }
            }
        }

        didMethodParameters.add(NamedDidMethodParameters.UPDATE_KEYS, updateKeysJsonArray);

        /*
        As described by https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters:

        A JSON array of strings that are hashes of multikey formatted public keys that MAY be added to the 'updateKeys' list in the next log entry.
        At least one entry of 'nextKeyHashes' MUST be added to the next 'updateKeys' list.

        - The process for generating the hashes and additional details for using pre-rotation are defined
          in the Pre-Rotation Key Hash Generation and Verification section of this specification.
        - If not set in the first log entry, its value defaults to an empty array ([]).
        - If not set in other log entries, its value is retained from the most recent prior value.
        - Once the 'nextKeyHashes' parameter has been set to a non-empty array, Key Pre-Rotation is active.
          While active, the properties 'nextKeyHashes' and 'updateKeys' MUST be present in all log entries.
        - While Key Pre-Rotation is active, ALL multikey formatted public keys added in a new 'updateKeys' list
          MUST have their hashes listed in the 'nextKeyHashes' list from the previous log entry.
        - A DID Controller MAY include extra hashes in the 'nextKeyHashes' array that are not subsequently used in an 'updateKeys' entry.
          Any unused hashes in 'nextKeyHashes' arrays are ignored.
        - The value of 'nextKeyHashes' MAY be set to an empty array ([]) to deactivate pre-rotation.
          For additional details about turning off pre-rotation, see the Pre-Rotation Key Hash Generation and Verification section of this specification.
         */
        var nextKeyHashesJsonArray = new JsonArray();
        // Once the nextKeys/nextKeyHashes parameters has been set to a non-empty array, Key Pre-Rotation is active.
        try {
            nextKeyHashesJsonArray.addAll(NextKeyHashesDidMethodParameter.collectHashesIntoJsonArray(nextKeyHashesDidMethodParameters));
        } catch (NextKeyHashesDidMethodParameterException e) {
            throw new DidLogCreatorStrategyException(e);
        }

        if (!nextKeyHashesJsonArray.isEmpty()) {
            didMethodParameters.add(NamedDidMethodParameters.NEXT_KEY_HASHES, nextKeyHashesJsonArray);
        }

        // MUST set portable to false in the first DID log entry.
        // See "Swiss e-ID and trust infrastructure: Interoperability profile" available at:
        //     https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#didtdwdidwebvh
        didMethodParameters.addProperty("portable", false);

        // Since v1.0 (https://identity.foundation/didwebvh/v1.0/#didtdw-version-changelog):
        //            Removes the cryptosuite parameter, moving it to implied based on the method parameter.
        //cryptosuite: Option::None,

        return didMethodParameters;
    }

    /**
     * Builds a <a href="https://identity.foundation/didwebvh/v1.0/#method-specific-identifier">method-specific identifier</a>
     * w.r.t. <a href="https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation">DID-to-HTTPS-transformation</a>.
     * <p>
     * See <a href="https://identity.foundation/didwebvh/v1.0/#example-3">example</a>.
     *
     * @param identifierRegistryUrl an HTTPS URL to transform from
     * @return a DID method-specific identifier
     */
    protected String buildDid(URL identifierRegistryUrl) {

        var did = "%s:{SCID}:%s".formatted(getDidMethod().getPrefix(), identifierRegistryUrl.getHost());
        int port = identifierRegistryUrl.getPort(); // the port number, or -1 if the port is not set
        if (port != -1) {
            did = "%s%%3A%d".formatted(did, port);
        }
        String path = identifierRegistryUrl.getPath(); // the path part of this URL, or an empty string if one does not exist
        if (!path.isEmpty()) {
            did = "%s%s".formatted(did,
                    path.replace("/did.jsonl", "") // cleanup
                            .replace("/", ":")); // w.r.t. https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation);
        }

        return did;
    }

    /**
     *
     * @param identifierRegistryUrl
     * @param authenticationKeys
     * @param assertionMethodKeys
     * @param forceOverwrite
     * @return JSON object representing a valid DID document w.r.t. to supplied verification material
     * @throws DidLogCreatorStrategyException if no verification material is supplied
     */
    @SuppressWarnings({"PMD.CyclomaticComplexity"})
    protected JsonObject createDidDoc(URL identifierRegistryUrl,
                                      Map<String, String> authenticationKeys,
                                      Map<String, String> assertionMethodKeys,
                                      boolean forceOverwrite) throws DidLogCreatorStrategyException {

        var did = buildDid(identifierRegistryUrl);

        var context = new JsonArray();
        // See "Swiss e-ID and trust infrastructure: Interoperability profile" available at:
        //     https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#did-document-format
        context.add("https://www.w3.org/ns/did/v1");
        context.add("https://w3id.org/security/jwk/v1");

        // Create initial did doc with placeholder
        var didDoc = new JsonObject();
        didDoc.add("@context", context);
        didDoc.addProperty("id", did);
        // CAUTION The "controller" property must not be present w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDSYS-352
        // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
        //didDoc.addProperty("controller", did);

        var verificationMethod = new JsonArray();

        if ((authenticationKeys == null || authenticationKeys.isEmpty())
                && (assertionMethodKeys == null || assertionMethodKeys.isEmpty())) {
            throw new DidLogCreatorStrategyException("No verification material (authentication or assertion) supplied");
        }

        if (authenticationKeys != null && !authenticationKeys.isEmpty()) {

            var authentication = new JsonArray();
            for (var key : authenticationKeys.entrySet()) {
                authentication.add(did + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(did, key.getKey(), key.getValue()));
            }

            didDoc.add("authentication", authentication);
        }

        if (assertionMethodKeys != null && !assertionMethodKeys.isEmpty()) {

            var assertionMethod = new JsonArray();
            for (var key : assertionMethodKeys.entrySet()) {
                assertionMethod.add(did + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(did, key.getKey(), key.getValue()));
            }

            didDoc.add("assertionMethod", assertionMethod);
        }

        didDoc.add("verificationMethod", verificationMethod);

        return didDoc;
    }

    protected boolean isVerificationMethodKeyProviderLegal(VerificationMethodKeyProvider verificationMethodKeyProvider) {
        if (this.didLogMeta.isKeyPreRotationActivated()) {
            return this.didLogMeta.isPreRotatedUpdateKey(verificationMethodKeyProvider.getVerificationKeyMultibase());
        } else {
            return verificationMethodKeyProvider.isKeyMultibaseInSet(this.didLogMeta.getParams().getUpdateKeys());
        }
    }
}