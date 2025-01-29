package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import ch.admin.eid.didtoolbox.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.io.*;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

/**
 * {@link TdwUpdater} is the class in charge of <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log update (rotate).
 * <p>
 * By relying fully on the <a href="https://en.wikipedia.org/wiki/Builder_pattern">Builder (creational) Design Pattern</a>, thus making heavy use of
 * <a href="https://en.wikipedia.org/wiki/Fluent_interface">fluent design</a>,
 * it is intended to be instantiated exclusively via its static {@link #builder()} method.
 * <p>
 * Once a {@link TdwUpdater} object is "built", creating a <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a>
 * log goes simply by calling {@link #update(String, String)} method. Optionally, but most likely, an already existing key material will
 * be also used in the process, so for the purpose there are further fluent methods available:
 * <ul>
 * <li>{@link TdwUpdater.TdwUpdaterBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} for setting the update (Ed25519) key</li>
 * <li>{@link TdwUpdater.TdwUpdaterBuilder#authenticationKeys(Map)} for setting authentication
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * <li>{@link TdwUpdater.TdwUpdaterBuilder#assertionMethodKeys(Map)} for setting/assertion
 * (EC/P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a>) keys</li>
 * </ul>
 * To load keys from the file system, the following helpers are available:
 * <ul>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(File, File)} for loading the update (Ed25519) key from
 * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> files</li>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(InputStream, String, String)} for loading the update (Ed25519) key from Java KeyStore (JKS) files</li>
 * <li>{@link JwkUtils#loadECPublicJWKasJSON(File, String)} for loading authentication/assertion public
 * EC P-256 <a href="https://www.w3.org/TR/vc-jws-2020/#json-web-key-2020">JsonWebKey2020</a> keys from
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">PEM</a> files</li>
 * </ul>
 * For instance:
 * <pre>
 * {@code
 *     package mypackage;
 *
 *     import ch.admin.bj.swiyu.didtoolbox.*;
 *     import java.net.*;
 *
 *     public static void main(String... args) {
 *
 *         String didLogEntryWithGeneratedKeys = null;
 *         String didLogEntryWithExternalKeys = null;
 *         try {
 *             URL identifierRegistryUrl = URL.of(new URI("https://127.0.0.1:54858/123456789/123456789/did.jsonl"), null);
 *
 *             // NOTE that all required keys will be generated here as well, as no explicit verificationMethodKeyProvider is set
 *             didLogEntryWithGeneratedKeys = TdwCreator.builder()
 *                 .build()
 *                 .create(identifierRegistryUrl);
 *
 *             // Using already existing key material
 *             didLogEntryWithExternalKeys = TdwCreator.builder()
 *                 .verificationMethodKeyProvider(new Ed25519VerificationMethodKeyProviderImpl(new File("private-key.pem"), new File("public-key.pem")))
 *                 .assertionMethodKeys(Map.of(
 *                     "my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File("assert-key-01.pub"), "my-assert-key-01")
 *                 ))
 *                 .authenticationKeys(Map.of(
 *                     "my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File("auth-key-01.pub"), "my-auth-key-01")
 *                 ))
 *                 .build()
 *                 .create(identifierRegistryUrl);
 *
 *         } catch (Exception e) {
 *             // some exc. handling goes here
 *             System.exit(1);
 *         }
 *
 *         // do something with the didLogEntry* vars here
 *     }
 * }
 * </pre>
 */
@Builder
@Getter
public class TdwUpdater {

    private static String SCID_PLACEHOLDER = "{SCID}";

    @Getter(AccessLevel.PRIVATE)
    //@Setter(AccessLevel.PUBLIC)
    private Map<String, String> assertionMethodKeys;
    @Getter(AccessLevel.PRIVATE)
    //@Setter(AccessLevel.PUBLIC)
    private Map<String, String> authenticationKeys;
    @Builder.Default
    @Getter(AccessLevel.PRIVATE)
    //@Setter(AccessLevel.PUBLIC)
    private VerificationMethodKeyProvider verificationMethodKeyProvider = new Ed25519VerificationMethodKeyProviderImpl();
    // TODO private File dirToStoreKeyPair;

    private static JsonObject verificationMethodAsJsonObject(VerificationMethod vm) {
        var publicKeyJwk = vm.getPublicKeyJwk();

        JsonObject publicKeyJwkJsonObj = new JsonObject();
        publicKeyJwkJsonObj.addProperty("kty", publicKeyJwk.getKty());
        publicKeyJwkJsonObj.addProperty("crv", publicKeyJwk.getCrv());
        publicKeyJwkJsonObj.addProperty("kid", publicKeyJwk.getKid());
        publicKeyJwkJsonObj.addProperty("x", publicKeyJwk.getX());
        publicKeyJwkJsonObj.addProperty("y", publicKeyJwk.getY());

        JsonObject obj = new JsonObject();
        obj.addProperty("id", vm.getId());
        obj.addProperty("controller", vm.getController());
        obj.addProperty("type", "JsonWebKey2020");
        obj.add("publicKeyJwk", publicKeyJwkJsonObj);

        return obj;
    }

    /**
     * Updates a valid <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log by taking into account other
     * features of this {@link TdwUpdater} object, optionally customized by previously calling fluent methods like
     * {@link TdwUpdater.TdwUpdaterBuilder#verificationMethodKeyProvider}, {@link TdwUpdater.TdwUpdaterBuilder#authenticationKeys(Map)} or
     * {@link TdwUpdater.TdwUpdaterBuilder#assertionMethodKeys(Map)}.
     *
     * @param didTDW a TDW-specific identifier in its entirety w.r.t.
     *               <a href="https://identity.foundation/didwebvh/v0.3/#method-specific-identifier">method-specific-identifier</a>
     * @return a valid <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log
     * @throws IOException if creation fails for whatever reason
     * @see #update(String, String, ZonedDateTime)
     */
    public String update(String didTDW, String oldDidLog) throws IOException {
        return update(didTDW, oldDidLog, ZonedDateTime.now());
    }

    private static JsonObject buildVerificationMethodWithPublicKeyJwk(String didTDW, String keyID, String jwk, File jwksFile) throws IOException {

        String publicKeyJwk = jwk;
        if (publicKeyJwk == null || publicKeyJwk.isEmpty()) {
            publicKeyJwk = JwkUtils.generatePublicEC256(keyID, jwksFile);
        }

        JsonObject verificationMethodObj = new JsonObject();
        verificationMethodObj.addProperty("id", didTDW + "#" + keyID);
        verificationMethodObj.addProperty("controller", didTDW);
        verificationMethodObj.addProperty("type", "JsonWebKey2020");
        //verificationMethodObj.addProperty("publicKeyMultibase", publicKeyMultibase);
        verificationMethodObj.add("publicKeyJwk", JsonParser.parseString(publicKeyJwk).getAsJsonObject());

        return verificationMethodObj;
    }

    /**
     * Updates a <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log for a supplied datetime.
     * <p>
     * This package-scope method is certainly more potent than the public one.
     * <p>
     * <b>However, it is introduced for the sake of testability only.</b>
     *
     * @param didTDW a TDW-specific identifier in its entirety w.r.t.
     *               <a href="https://identity.foundation/didwebvh/v0.3/#method-specific-identifier">method-specific-identifier</a>
     * @param zdt    a date-time with a time-zone in the ISO-8601 calendar system
     * @return
     * @throws IOException
     */
    String update(String didTDW, String didLog, ZonedDateTime zdt) throws IOException {

        // Common sense
        var did = new Did(didTDW);
        DidDoc oldDidDoc;
        try {
            oldDidDoc = did.resolve(didLog);
        } catch (DidResolveException e) {
            throw new IOException(e);
        } finally {
            did.close();
        }

        var didLogMeta = DidLogMetaPeeker.peek(didLog);

        // CAUTION Only activated DIDs can be updated
        if (didLogMeta.params.deactivated != null && didLogMeta.params.deactivated) {
            throw new IOException("DID already deactivated");
        }

        if (!didLogMeta.params.updateKeys.contains(this.verificationMethodKeyProvider.getVerificationKeyMultibase())) {
            throw new IOException("Update key mismatch");
        }

        List<VerificationMethod> oldAuthentication = oldDidDoc.getAuthentication();
        List<VerificationMethod> oldAssertionMethod = oldDidDoc.getAssertionMethod();
        //List<VerificationMethod> oldVerificationMethod = oldDidDoc.getVerificationMethod();

        // Create initial did doc with placeholder
        var didDoc = new JsonObject();

        // take over context
        var context = new JsonArray();
        for (var ctx : oldDidDoc.getContext()) {
            context.add(ctx);
        }
        didDoc.add("@context", context);

        didDoc.addProperty("id", didTDW);
        // "controller" is omitted w.r.t. https://jira.bit.admin.ch/browse/EIDSYS-352
        //didDoc.addProperty("controller", didTDW);

        var verificationMethod = new JsonArray();

        if (this.authenticationKeys != null && !this.authenticationKeys.isEmpty()) {

            JsonArray authentication = new JsonArray();
            for (var key : this.authenticationKeys.entrySet()) {

                if (oldAuthentication.stream().anyMatch(num -> {
                    String[] split = num.getId().split("#");
                    return split.length == 2 && split[1].equals(key.getKey());
                })) {
                    throw new IOException("The authentication key exists already: " + key.getKey());
                }

                authentication.add(didTDW + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, key.getKey(), key.getValue(), null));
            }

            // add the rest that was there already
            for (var auth : oldDidDoc.getAuthentication()) {
                authentication.add(auth.getId());
            }

            didDoc.add("authentication", authentication);
        }

        if (this.assertionMethodKeys != null && !this.assertionMethodKeys.isEmpty()) {

            JsonArray assertionMethod = new JsonArray();
            for (var key : this.assertionMethodKeys.entrySet()) {

                if (oldAssertionMethod.stream().anyMatch(num -> {
                    String[] split = num.getId().split("#");
                    return split.length == 2 && split[1].equals(key.getKey());
                })) {
                    throw new IOException("The assertion method key exists already: " + key.getKey());
                }

                assertionMethod.add(didTDW + "#" + key.getKey());
                verificationMethod.add(buildVerificationMethodWithPublicKeyJwk(didTDW, key.getKey(), key.getValue(), null));
            }

            // add the rest that was there already
            for (var a : oldDidDoc.getAssertionMethod()) {
                assertionMethod.add(a.getId());
            }

            didDoc.add("assertionMethod", assertionMethod);
        }

        // add the rest that was there already
        for (var vm : oldDidDoc.getVerificationMethod()) {

            var type = vm.getVerificationType();
            if (!type.equals(VerificationType.JSON_WEB_KEY2020)) {
                throw new IOException("Verification method type not supported: ");
            }

            verificationMethod.add(verificationMethodAsJsonObject(vm));
        }

        didDoc.add("verificationMethod", verificationMethod);

        // The DID log entry is an input JSON array that when completed contains the following items:
        // [ versionId, versionTime, parameters, DIDDoc State, Data Integrity Proof ].

        var didLogEntryWithoutProofAndSignature = new JsonArray();

        // https://identity.foundation/didwebvh/v0.3/#entry-hash-generation-and-verification:
        // For the first log entry, the predecessor versionId is the SCID (itself a hash),
        // while for all other entries it is the versionId item from the previous log entry.
        didLogEntryWithoutProofAndSignature.add(didLogMeta.lastVersionId);

        // The second item in the input JSON array MUST be a valid ISO8601 date/time string,
        // and that the represented time MUST be before or equal to the current time.
        //
        // The versionTime for each log entry MUST be greater than the previous entry’s time.
        // The versionTime of the last entry MUST be earlier than the current time.
        didLogEntryWithoutProofAndSignature.add(DateTimeFormatter.ISO_INSTANT.format(zdt.truncatedTo(ChronoUnit.SECONDS)));

        // The third item in the input JSON array MUST be the parameters JSON object.
        // The parameters are used to configure the DID generation and verification processes.
        // All parameters MUST be valid and all required values in the first version of the DID MUST be present.
        didLogEntryWithoutProofAndSignature.add(JsonParser.parseString("{\"witnessThreshold\": 0}").getAsJsonObject()); // CAUTION params remain the same
        //didLogEntryWithoutProofAndSignature.add(new JsonObject()); // CAUTION params remain the same, but this throws "ch.admin.eid.didresolver.InternalException: called `Option::unwrap()` on a `None` value"

        // The fourth item in the input JSON array MUST be the JSON object {"value": <diddoc> }, where <diddoc> is the initial DIDDoc as described in the previous step 3.
        var didDocJson = new JsonObject();
        didDocJson.add("value", didDoc);
        didLogEntryWithoutProofAndSignature.add(didDocJson);

        // See https://identity.foundation/didwebvh/v0.3/#generate-entry-hash
        // This JSON is the input to the entryHash generation process – with the SCID as the first item of the array.
        // Once the process has run, the version number of this first version of the DID (1),
        // a dash - and the resulting output hash replace the SCID as the first item in the array – the versionId.
        var entryHash = JCSHasher.buildSCID(didLogEntryWithoutProofAndSignature);

        JsonArray didLogEntryWithProof = new JsonArray();
        didLogEntryWithProof.add(didLogMeta.lastVersionNumber + 1 + "-" + entryHash);
        didLogEntryWithProof.add(didLogEntryWithoutProofAndSignature.get(1));
        didLogEntryWithProof.add(JsonParser.parseString("{\"witnessThreshold\": 0}").getAsJsonObject()); // CAUTION params remain the same
        //didLogEntryWithProof.add(new JsonObject()); // CAUTION params remain the same, but this throws "ch.admin.eid.didresolver.InternalException: called `Option::unwrap()` on a `None` value"
        didLogEntryWithProof.add(didLogEntryWithoutProofAndSignature.get(3));

        /*
        https://identity.foundation/trustdidweb/v0.3/#data-integrity-proof-generation-and-first-log-entry:
        The last step in the creation of the first log entry is the generation of the data integrity proof.
        One of the keys in the updateKeys parameter MUST be used (in the form of a did:key) to generate the signature in the proof,
        with the versionId value (item 1 of the did log) used as the challenge item.
        The generated proof is added to the JSON as the fifth item, and the entire array becomes the first entry in the DID Log.
         */
        var proofs = new JsonArray();
        var proof = JCSHasher.buildDataIntegrityProof(didDoc, false, this.verificationMethodKeyProvider, didLogMeta.lastVersionNumber + 1, entryHash, "authentication", zdt);
        // CAUTION Set proper "verificationMethod"
        proof.addProperty("verificationMethod", "did:key:" + didLogMeta.params.updateKeys.getLast() + '#' + didLogMeta.params.updateKeys.getLast());
        proofs.add(proof);
        didLogEntryWithProof.add(proofs);
        return didLogEntryWithProof.toString();
    }
}