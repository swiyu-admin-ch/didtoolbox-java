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
import java.util.HexFormat;

class JCSHasher {

    /**
     * To generate the required SCID for a did:tdw DID, the DID Controller MUST execute the following function:
     * base58btc(multihash(JCS(preliminary log entry with placeholders), <hash algorithm>))
     * Where
     * JCS is an implementation of the JSON Canonicalization Scheme [RFC8785]. It outputs a canonicalized representation of its JSON input.
     * multihash is an implementation of the multihash specification. Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
     * <hash algorithm> is the hash algorithm used by the DID Controller. The hash algorithm MUST be one listed in the parameters defined by the version of the did:tdw specification being used by the DID Controller.
     * base58btc is an implementation of the base58btc function. Its output is the base58 encoded string of its input.
     *
     * @return
     */
    static String buildSCID(JsonArray didLog) throws NoSuchAlgorithmException, IOException {
        var jsc = (new JsonCanonicalizer(didLog.toString())).getEncodedString();
        return Base58.encode(multihash(jsc));
    }

    static String multihashJsonObject(JsonObject obj) throws NoSuchAlgorithmException, IOException {
        var jsc = (new JsonCanonicalizer(obj.toString())).getEncodedString();
        return Base58.encode(multihash(jsc));
    }

    /**
     * multihash is an implementation of the multihash specification (https://www.w3.org/TR/controller-document/#multihash).
     * Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
     *
     * @param str
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    static byte[] multihash(String str) throws NoSuchAlgorithmException, IOException {

        MessageDigest hasher = MessageDigest.getInstance("SHA-256");
        hasher.update(str.getBytes(StandardCharsets.UTF_8));
        byte[] digest = hasher.digest();

        // multihash is an implementation of the multihash specification (https://www.w3.org/TR/controller-document/#multihash).
        // Its output is a hash of the input using the associated <hash algorithm>, prefixed with a hash algorithm identifier and the hash size.
        // Multihash Identifier	Multihash Header	Description
        // sha2-256	            0x12	            SHA-2 with 256 bits (32 bytes) of output, as defined by [RFC6234].
        ByteBuffer buff = ByteBuffer.allocate(2 + digest.length);
        // See https://github.com/multiformats/multicodec/blob/master/table.csv#L98
        buff.put((byte) 0x12);          // hash algorithm (sha2-256) identifier
        buff.put((byte) digest.length); // hash size (in bytes)
        buff.put(digest);

        return buff.array();
    }

    private static String hashAsHex(String json) throws NoSuchAlgorithmException, IOException {
        MessageDigest hasher = MessageDigest.getInstance("SHA-256");
        hasher.update(((new JsonCanonicalizer(json)).getEncodedString()).getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hasher.digest());
    }

    static String hashJsonObjectAsHex(JsonObject json) throws NoSuchAlgorithmException, IOException {
        return hashAsHex(json.toString());
    }

    static String hashJsonArray(JsonArray json) throws NoSuchAlgorithmException, IOException {
        return hashAsHex(json.toString());
    }

    /**
     * As specifed https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022
     */
    static String buildProof(JsonObject proof, JsonObject doc, Signer signer) throws NoSuchAlgorithmException, IOException {

        String docHashHex = JCSHasher.hashJsonObjectAsHex(doc);
        String proofHashHex = JCSHasher.hashJsonObjectAsHex(proof);

        var signature = signer.signBytes(HexFormat.of().parseHex(proofHashHex + docHashHex));
        //String combinedHashHex = HexFormat.of().formatHex(signature);

        return 'z' + Base58.encode(signature);
    }
}
