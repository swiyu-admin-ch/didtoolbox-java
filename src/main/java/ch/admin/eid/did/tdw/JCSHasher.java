package ch.admin.eid.did.tdw;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

class JCSHasher {

    /**
     *
     * @param json
     * @return Returns a hexadecimal string formatted from...
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    private static String hash(String json) throws NoSuchAlgorithmException, IOException {
        MessageDigest hasher = MessageDigest.getInstance("SHA-256");
        hasher.update(((new JsonCanonicalizer(json)).getEncodedString()).getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hasher.digest());
    }

    /**
     *
     * @param json
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    static String hashJsonObject(JsonObject json) throws NoSuchAlgorithmException, IOException {
        return hash(json.toString());
    }

    /**
     *
     * @param json
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    static String hashJsonArray(JsonArray json) throws NoSuchAlgorithmException, IOException {
        return hash(json.toString());
    }

}
