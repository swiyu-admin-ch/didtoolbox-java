package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonElement;
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

public final class JCSHasher {

    public static final String DATA_INTEGRITY_PROOF = "DataIntegrityProof";
    public static final String EDDSA_JCS_2022 = "eddsa-jcs-2022";
    public static final String DID_KEY = "did:key:";
    public static final String PROOF_PURPOSE_AUTHENTICATION = "authentication";
    public static final String PROOF_PURPOSE_ASSERTION_METHOD = "assertionMethod";

    private JCSHasher() {
    }

    /**
     * To generate the SCID (<b>Self-Certifying IDentifier</b>: <i>An object identifier derived from initial data such that an
     * attacker could not create a new object with the same identifier</i>)
     * for a {@code did:*} DID (e.g. {@code did:webvh}), the DID Controller MUST execute the following function:
     * <p>{@code base58btc(multihash(JCS(preliminary log entry with placeholders), <hash algorithm>))}
     * <p>Where
     * <ol>
     * <li>{@code JCS} is an implementation of the <a href="https://www.rfc-editor.org/rfc/rfc8785">JSON Canonicalization Scheme [RFC8785]</a>. It outputs a canonicalized representation of its JSON input.
     * <li>{@code multihash} is an implementation of the multihash specification. Its output is a hash of the input using the associated {@code <hash algorithm>}, prefixed with a hash algorithm identifier and the hash size.
     * <li>{@code <hash algorithm>} is the hash algorithm used by the DID Controller. The hash algorithm MUST be one listed in the parameters defined by the version of the did:tdw specification being used by the DID Controller.
     * <li>{@code base58btc} is an implementation of the base58btc function. Its output is the base58 encoded string of its input.
     * </ol>
     * As such, the helper can be used out-of-the-box for the purpose of <a href="https://identity.foundation/didwebvh/v1.0/#generate-scid">generate-scid</a>.
     *
     * @return a valid {@code SCID} for the supplied JSON input
     */
    public static String buildSCID(JsonElement jsonData) throws IOException {
        return Base58.encode(multihash((new JsonCanonicalizer(jsonData.toString())).getEncodedString()));
    }

    /**
     * @deprecated Use {@link #buildSCID(JsonElement)} instead, whenever possible.
     */
    @Deprecated
    public static String buildSCID(String jsonData) throws IOException {
        return Base58.encode(multihash((new JsonCanonicalizer(jsonData)).getEncodedString()));
    }

    /**
     * This helper calculates the hash string as {@code base58btc(multihash(multikey))}, where:
     * <ol>
     *      <li>{@code multikey} is the multikey representation of a public key</li>
     *      <li>{@code multihash} is an implementation of the <a href="https://www.w3.org/TR/controller-document/#multihash">multihash</a> specification.
     *      Its output is a hash of the input using the associated {@code <hash algorithm>},
     *      prefixed with a hash algorithm identifier and the hash size.</li>
     *      <li>{@code <hash algorithm>} is the hash algorithm used by the DID Controller.
     *      The hash algorithm MUST be one listed in the parameters defined by the version of a {@code did:*} (e.g. {@code did:webvh})
     *      specification being used by the DID Controller.</li>
     *      <li>{@code base58btc} is an implementation of the base58btc function (converts data to a {@code base58} encoding).
     *      Its output is the base58 encoded string of its input.</li>
     * </ol>
     * As such, the helper can be used out-of-the-box for the purpose of <a href="https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification">pre-rotation-key-hash-generation-and-verification</a>.
     *
     * @param key multikey to build hash for
     * @return hash string for the supplied multikey
     */
    public static String buildNextKeyHash(String key) {
        return Base58.encode(multihash(key.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * multihash is an implementation of the <a href="https://www.w3.org/TR/controller-document/#multihash">multihash</a> specification.
     * Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
     *
     * @param str
     * @return
     */
    static byte[] multihash(String str) {
        return multihash(str.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * multihash is an implementation of the <a href="https://www.w3.org/TR/controller-document/#multihash">multihash</a> specification.
     * Its output is a hash of the input using the associated {@code <hash algorithm>}, prefixed with a hash algorithm identifier and the hash size.
     *
     * @param input the array of bytes to be hashed.
     * @return hashed bytes
     */
    static byte[] multihash(byte[] input) {

        MessageDigest hasher;
        try {
            hasher = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        hasher.update(input);
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

    static String hashAsHex(JsonElement json) throws IOException {
        MessageDigest hasher;
        try {
            hasher = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        hasher.update(((new JsonCanonicalizer(json.toString())).getEncodedString()).getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hasher.digest());
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
     * @param challenge                     self-explanatory
     * @param proofPurpose                  typically "assertionMethod" or "authentication"
     * @param dateTime                      of the proof creation
     * @return JsonObject representing the data integrity proof
     * @throws IOException may come from a hasher
     */
    public static JsonObject buildDataIntegrityProof(JsonObject unsecuredDocument,
                                                     boolean useContext,
                                                     VerificationMethodKeyProvider verificationMethodKeyProvider,
                                                     String challenge,
                                                     String proofPurpose,
                                                     ZonedDateTime dateTime)
            throws IOException {

        /*
        https://identity.foundation/didwebvh/v0.3/#data-integrity-proof-generation-and-first-log-entry:
        The last step in the creation of the first log entry is the generation of the data integrity proof.
        One of the keys in the updateKeys parameter MUST be used (in the form of a did:key) to generate the signature in the proof,
        with the versionId value (item 1 of the did log) used as the challenge item.
        The generated proof is added to the JSON as the fifth item, and the entire array becomes the first entry in the DID Log.
         */

        var proof = new JsonObject();

        // If unsecuredDocument.@context is present, set proof.@context to unsecuredDocument.@context.
        var ctx = unsecuredDocument.get("@context");
        if (ctx != null && useContext) {
            proof.add("@context", ctx);
        }

        proof.addProperty("type", DATA_INTEGRITY_PROOF);
        // According to https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
        proof.addProperty("cryptosuite", EDDSA_JCS_2022);
        proof.addProperty("created", DateTimeFormatter.ISO_INSTANT.format(dateTime.truncatedTo(ChronoUnit.SECONDS)));

        /*
        The data integrity proof verificationMethod is the did:key from the first log entry, and the challenge is the versionId from this log entry.
         */
        proof.addProperty("verificationMethod", DID_KEY + verificationMethodKeyProvider.getVerificationKeyMultibase() + '#' + verificationMethodKeyProvider.getVerificationKeyMultibase());
        proof.addProperty("proofPurpose", proofPurpose);
        if (challenge != null) {
            proof.addProperty("challenge", challenge);
        }

        String docHashHex = hashAsHex(unsecuredDocument);
        String proofHashHex = hashAsHex(proof);

        var signature = verificationMethodKeyProvider.generateSignature(HexFormat.of().parseHex(proofHashHex + docHashHex));
        //String signatureHex = HexFormat.of().formatHex(signature);
        //String verifyingKeyHex = HexFormat.of().formatHex(verificationMethodKeyProvider.verifyingKey);

        // See https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022
        //     https://www.w3.org/TR/controller-document/#multibase-0
        proof.addProperty("proofValue", 'z' + Base58.encode(signature));

        return proof;
    }
}
