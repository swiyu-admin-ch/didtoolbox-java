package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.ipfs.multibase.Base58;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;

class JCSHasher {

    /**
     * To generate the required SCID for a did:tdw DID, the DID Controller MUST execute the following function:
     * <p>base58btc(multihash(JCS(preliminary log entry with placeholders), &lt;hash algorithm&gt;))
     * <p>Where
     * <li>JCS is an implementation of the JSON Canonicalization Scheme [RFC8785]. It outputs a canonicalized representation of its JSON input.
     * <li>multihash is an implementation of the multihash specification. Its output is a hash of the input using the associated &lt;hash algorithm&gt;, prefixed with a hash algorithm identifier and the hash size.
     * <li>&lt;hash algorithm&gt; is the hash algorithm used by the DID Controller. The hash algorithm MUST be one listed in the parameters defined by the version of the did:tdw specification being used by the DID Controller.
     * <li>base58btc is an implementation of the base58btc function. Its output is the base58 encoded string of its input.
     *
     * @return
     */
    static String buildSCID(JsonArray didLog) throws IOException {
        var jsc = (new JsonCanonicalizer(didLog.toString())).getEncodedString();
        return Base58.encode(multihash(jsc));
    }

    static String multihashJsonObject(JsonObject obj) throws IOException {
        var jsc = (new JsonCanonicalizer(obj.toString())).getEncodedString();
        return Base58.encode(multihash(jsc));
    }

    /**
     * multihash is an implementation of the multihash specification (https://www.w3.org/TR/controller-document/#multihash).
     * Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
     *
     * @param str
     * @return
     */
    static byte[] multihash(String str) {

        MessageDigest hasher = null;
        try {
            hasher = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        hasher.update(str.getBytes(StandardCharsets.UTF_8));
        byte[] digest = hasher.digest();

        // multihash is an implementation of the multihash specification (https://www.w3.org/TR/controller-document/#multihash).
        // Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
        // Multihash Identifier	Multihash Header	Description
        // sha2-256	            0x12	            SHA-2 with 256 bits (32 bytes) of output, as defined by [RFC6234].
        ByteBuffer buff = ByteBuffer.allocate(2 + digest.length);
        buff.put((byte) 0x12);          // hash algorithm (sha2-256) identifier
        buff.put((byte) digest.length); // hash size (in bytes)
        buff.put(digest);

        return buff.array();
    }

    private static String hashAsHex(String json) throws IOException {

        MessageDigest hasher = null;
        try {
            hasher = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        hasher.update(((new JsonCanonicalizer(json)).getEncodedString()).getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hasher.digest());
    }

    static String hashJsonObjectAsHex(JsonObject json) throws IOException {
        return hashAsHex(json.toString());
    }

    static String hashJsonArrayAsHex(JsonArray json) throws IOException {
        return hashAsHex(json.toString());
    }

    /**
     * As specified by <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">...</a>.
     * <p>See example: <a href="https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022">...</a>
     *
     * <p>A proof contains the attributes specified in the <a href="https://www.w3.org/TR/vc-data-integrity/#proofs">Proofs</a> section
     * of <a href="https://www.w3.org/TR/vc-di-eddsa/#bib-vc-data-integrity">VC-DATA-INTEGRITY</a> with the following restrictions.
     *
     * <p>The type property MUST be DataIntegrityProof.
     *
     * <p>The cryptosuite property of the proof MUST be "eddsa-rdfc-2022" or "eddsa-jcs-2022".
     * CAUTION This implementation supports currently only "eddsa-jcs-2022" as specified by https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022.
     *
     * <p>The proofValue property of the proof MUST be a detached EdDSA signature produced according to
     * <a href="https://www.w3.org/TR/vc-di-eddsa/#bib-rfc8032">RFC8032</a>,
     * encoded using the base-58-btc header and alphabet as described in the
     * <a href="https://www.w3.org/TR/controller-document/#multibase-0">Multibase</a> section of
     * <a href="https://www.w3.org/TR/controller-document/">Controlled Identifier Document</a>.
     *
     * @param unsecuredDocument             to create a proof for
     * @param verificationMethodKeyProvider to use for signing the proofValue
     * @param versionId                     relevant for the "challenge" property, if required
     * @param entryHash                     relevant for the "challenge" property, if required
     * @param proofPurpose                  typically "assertionMethod" or "authentication"
     * @param dateTime                      of the proof creation
     * @return JsonObject representing the data integrity proof
     * @throws IOException may come from a hasher
     */
    static JsonObject buildDataIntegrityProof(JsonObject unsecuredDocument,
                                              boolean useContext,
                                              VerificationMethodKeyProvider verificationMethodKeyProvider,
                                              int versionId,
                                              String entryHash,
                                              String proofPurpose,
                                              ZonedDateTime dateTime)
            throws IOException {

        /*
        https://identity.foundation/trustdidweb/v0.3/#data-integrity-proof-generation-and-first-log-entry:
        The last step in the creation of the first log entry is the generation of the data integrity proof.
        One of the keys in the updateKeys parameter MUST be used (in the form of a did:key) to generate the signature in the proof,
        with the versionId value (item 1 of the did log) used as the challenge item.
        The generated proof is added to the JSON as the fifth item, and the entire array becomes the first entry in the DID Log.
         */

        JsonObject proof = new JsonObject();

        // If unsecuredDocument.@context is present, set proof.@context to unsecuredDocument.@context.
        var ctx = unsecuredDocument.get("@context");
        if (ctx != null && useContext) {
            proof.add("@context", ctx);
        }

        proof.addProperty("type", "DataIntegrityProof");
        proof.addProperty("cryptosuite", "eddsa-jcs-2022");
        proof.addProperty("created", DateTimeFormatter.ISO_INSTANT.format(dateTime.truncatedTo(ChronoUnit.SECONDS)));

        /*
        The data integrity proof verificationMethod is the did:key from the first log entry, and the challenge is the versionId from this log entry.
         */
        proof.addProperty("verificationMethod", "did:key:" + verificationMethodKeyProvider.getVerificationKeyMultibase() + '#' + verificationMethodKeyProvider.getVerificationKeyMultibase());
        proof.addProperty("proofPurpose", proofPurpose);
        if (entryHash != null && !entryHash.isEmpty()) {
            proof.addProperty("challenge", versionId + "-" + entryHash);
        }

        String docHashHex = hashJsonObjectAsHex(unsecuredDocument);
        String proofHashHex = hashJsonObjectAsHex(proof);

        var signature = verificationMethodKeyProvider.generateSignature(HexFormat.of().parseHex(proofHashHex + docHashHex));
        //String signatureHex = HexFormat.of().formatHex(signature);
        //String verifyingKeyHex = HexFormat.of().formatHex(verificationMethodKeyProvider.verifyingKey);

        // See https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022
        //     https://www.w3.org/TR/controller-document/#multibase-0
        proof.addProperty("proofValue", 'z' + Base58.encode(signature));

        return proof;
    }
}
