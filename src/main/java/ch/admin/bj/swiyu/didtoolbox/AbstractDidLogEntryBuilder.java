package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Set;

public abstract class AbstractDidLogEntryBuilder {

    protected final static String SCID_PLACEHOLDER = "{SCID}";
    protected DidLogMeta didLogMeta;

    protected static JsonObject buildVerificationMethodWithPublicKeyJwk(String didTDW, String keyID, String jwk, File jwksFile,
                                                                        boolean forceOverwrite) throws IOException {

        String publicKeyJwk = jwk;
        if (publicKeyJwk == null || publicKeyJwk.isEmpty()) {
            publicKeyJwk = JwkUtils.generatePublicEC256(keyID, jwksFile, forceOverwrite);
        }

        return buildVerificationMethodWithPublicKeyJwk(didTDW, keyID, publicKeyJwk);
    }

    protected static JsonObject buildVerificationMethodWithPublicKeyJwk(String didTDW, String keyID, String publicKeyJwk) {

        JsonObject verificationMethodObj = new JsonObject();
        verificationMethodObj.addProperty("id", didTDW + "#" + keyID);
        // CAUTION The "controller" property must not be present w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDSYS-35
        // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
        //verificationMethodObj.addProperty("controller", didTDW);
        verificationMethodObj.addProperty("type", "JsonWebKey2020");
        // CAUTION The "publicKeyMultibase" property must not be present w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDOMNI-35
        // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
        //verificationMethodObj.addProperty("publicKeyMultibase", publicKeyMultibase);
        verificationMethodObj.add("publicKeyJwk", JsonParser.parseString(publicKeyJwk).getAsJsonObject());

        return verificationMethodObj;
    }

    protected static File createPrivateKeyDirectoryIfDoesNotExist(String pathname) throws IOException {
        var outputDir = new File(pathname);
        if (!outputDir.exists()) {
            try {
                return FilesPrivacy.createPrivateDirectory(outputDir.toPath(), false).toFile(); // may throw DirectoryNotEmptyException, SecurityException etc.
            } catch (DirectoryNotEmptyException | FileAlreadyExistsException | AccessDeniedException ex) {
                // the directory (if exists) must be empty with write access granted
                throw new IllegalArgumentException(ex);
                //} catch (AccessDeniedException ex) {
                //    throw new AccessDeniedException("Access denied to " + outputDir.getPath() + " due to: " + ex.getMessage());
            } catch (Throwable thr) {
                throw new IOException("Failed to create private directory " + pathname + " due to: " + thr.getMessage());
            }
        }

        return outputDir;
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

    protected JsonObject createDidParams(VerificationMethodKeyProvider verificationMethodKeyProvider,
                                         Set<File> updateKeys) throws IOException {

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
        if (updateKeys != null) {
            for (var pemFile : updateKeys) { // ...and then add the rest, if any
                String updateKey;
                try {
                    updateKey = PemUtils.parsePEMFilePublicKeyEd25519Multibase(pemFile);
                } catch (InvalidKeySpecException e) {
                    throw new IOException(e);
                }

                if (!updateKeysJsonArray.contains(new JsonPrimitive(updateKey))) { // it is a distinct list of keys, after all
                    updateKeysJsonArray.add(updateKey);
                }
            }
        }
        didMethodParameters.add("updateKeys", updateKeysJsonArray);

        // MUST set portable to false in the first DID log entry.
        // See "Swiss e-ID and trust infrastructure: Interoperability profile" available at:
        //     https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#didtdwdidwebvh
        didMethodParameters.addProperty("portable", false);

        // Since v1.0 (https://identity.foundation/didwebvh/v1.0/#didtdw-version-changelog):
        //            Removes the cryptosuite parameter, moving it to implied based on the method parameter.
        //cryptosuite: Option::None,

        return didMethodParameters;
    }

    protected JsonObject createDidDoc(URL identifierRegistryUrl,
                                      Map<String, String> authenticationKeys,
                                      Map<String, String> assertionMethodKeys,
                                      boolean forceOverwrite) throws IOException {

        // Method-Specific Identifier: https://identity.foundation/didwebvh/v1.0/#method-specific-identifier
        // W.r.t. https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation
        // See also https://identity.foundation/didwebvh/v1.0/#example-7
        var didTDW = "%s:{SCID}:%s".formatted(getDidMethod().getPrefix(), identifierRegistryUrl.getHost());
        int port = identifierRegistryUrl.getPort(); // the port number, or -1 if the port is not set
        if (port != -1) {
            didTDW += "%3A" + port;
        }
        String path = identifierRegistryUrl.getPath(); // the path part of this URL, or an empty string if one does not exist
        if (!path.isEmpty()) {
            didTDW += path.replace("/did.jsonl", "") // cleanup
                    .replaceAll("/", ":"); // w.r.t. https://identity.foundation/didwebvh/v1.0/#the-did-to-https-transformation
        }

        var context = new JsonArray();
        // See "Swiss e-ID and trust infrastructure: Interoperability profile" available at:
        //     https://github.com/e-id-admin/open-source-community/blob/main/tech-roadmap/swiss-profile.md#did-document-format
        context.add("https://www.w3.org/ns/did/v1");
        context.add("https://w3id.org/security/jwk/v1");

        // Create initial did doc with placeholder
        var didDoc = new JsonObject();
        didDoc.add("@context", context);
        didDoc.addProperty("id", didTDW);
        // CAUTION The "controller" property must not be present w.r.t.:
        // - https://jira.bit.admin.ch/browse/EIDSYS-352
        // - https://confluence.bit.admin.ch/display/EIDTEAM/DID+Doc+Conformity+Check
        //didDoc.addProperty("controller", didTDW);

        JsonArray verificationMethod = new JsonArray();

        if (authenticationKeys != null && !authenticationKeys.isEmpty()) {

            JsonArray authentication = new JsonArray();
            for (var key : authenticationKeys.entrySet()) {
                authentication.add(didTDW + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, key.getKey(), key.getValue(), null, forceOverwrite));
            }

            didDoc.add("authentication", authentication);

        } else {

            var outputDir = createPrivateKeyDirectoryIfDoesNotExist(".didtoolbox");
            verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, "auth-key-01", null, new File(outputDir, "auth-key-01"), forceOverwrite)); // default

            JsonArray authentication = new JsonArray();
            authentication.add(didTDW + "#" + "auth-key-01");
            didDoc.add("authentication", authentication);
        }

        if (assertionMethodKeys != null && !assertionMethodKeys.isEmpty()) {

            JsonArray assertionMethod = new JsonArray();
            for (var key : assertionMethodKeys.entrySet()) {
                assertionMethod.add(didTDW + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, key.getKey(), key.getValue(), null, forceOverwrite));
            }

            didDoc.add("assertionMethod", assertionMethod);

        } else {

            var outputDir = createPrivateKeyDirectoryIfDoesNotExist(".didtoolbox");
            verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, "assert-key-01", null, new File(outputDir, "assert-key-01"), forceOverwrite)); // default

            JsonArray assertionMethod = new JsonArray();
            assertionMethod.add(didTDW + "#" + "assert-key-01");
            didDoc.add("assertionMethod", assertionMethod);
        }

        didDoc.add("verificationMethod", verificationMethod);

        return didDoc;
    }

    protected static JsonObject initDidMethodParametersByLoadingUpdateKeys(Set<File> updateKeysFiles, Set<String> currentUpdateKeys)
            throws DidLogUpdaterStrategyException {

        var updateKeysJsonArray = new JsonArray();

        var newUpdateKeys = Set.of(updateKeysFiles.stream().map(file -> {
            try {
                return PemUtils.parsePEMFilePublicKeyEd25519Multibase(file);
            } catch (Throwable ignore) {
            }
            return null;
        }).toArray(String[]::new));

        if (!currentUpdateKeys.containsAll(newUpdateKeys)) { // need for change?

            String updateKey;
            for (var pemFile : updateKeysFiles) {
                try {
                    updateKey = PemUtils.parsePEMFilePublicKeyEd25519Multibase(pemFile);
                } catch (IOException | InvalidKeySpecException e) {
                    throw new DidLogUpdaterStrategyException(e);
                }

                // it is a distinct list of keys, after all
                if (!updateKeysJsonArray.contains(new JsonPrimitive(updateKey))) {
                    updateKeysJsonArray.add(updateKey);
                }
            }
        }

        var didMethodParameters = new JsonObject();
        if (!updateKeysJsonArray.isEmpty()) {
            didMethodParameters.add("updateKeys", updateKeysJsonArray);
        }

        return didMethodParameters;
    }
}