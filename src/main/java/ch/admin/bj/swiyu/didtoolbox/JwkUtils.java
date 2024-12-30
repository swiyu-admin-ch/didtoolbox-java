package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.text.ParseException;

class JwkUtils {

    /**
     * See https://connect2id.com/products/nimbus-jose-jwt/examples/jwk-retrieval
     *
     * @param f
     * @return
     * @throws IOException
     * @throws ParseException
     */
    static String load(File f, String kid) throws IOException, ParseException {
        if (!f.isFile() || !f.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", f.getAbsolutePath()));
        }

        var jwk = JWKSet.load(f).getKeyByKeyId(kid); // might be null
        if (jwk == null) {
            throw new ParseException(String.format("No such kid '%s' found in the file.", kid), 0);
        }
        return jwk.toPublicJWK().toJSONString();
    }

    /*
    static JWK loadKeyStore(String keyStoreFile, String password, String kid) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {

        return JWKSet.load(
                        KeyStore.getInstance(new File(keyStoreFile), password.toCharArray()),
                        s -> password.toCharArray())
                .getKeyByKeyId(kid);
    }
     */

    static String generateEd25519(String keyID, File jwksFile) throws com.nimbusds.jose.JOSEException, IOException {

        // Generate Ed25519 Octet key pair in JWK format, attach some metadata
        OctetKeyPair jwk = new OctetKeyPairGenerator(Curve.Ed25519)
                //.keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                //.keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                .keyID(keyID) // give the key a unique ID (optional)
                //.issueTime(new Date()) // issued-at timestamp (optional)
                .generate();

        if (jwksFile != null) {

            var jsonArray = new JsonArray();
            jsonArray.add(JsonParser.parseString(jwk.toJSONString()));
            var keys = new JsonObject();
            keys.add("keys", jsonArray);

            var w = new BufferedWriter(new FileWriter(jwksFile));
            try {
                w.write(keys.toString());
            } finally {
                w.close();
            }

            // A private key file should always get appropriate file permissions, if feasible
            PosixFileAttributeView posixFileAttributeView = Files.getFileAttributeView(jwksFile.toPath(), PosixFileAttributeView.class);
            if (!System.getProperty("os.name").toLowerCase().contains("win") && posixFileAttributeView != null) {
                Files.setPosixFilePermissions(jwksFile.toPath(), PosixFilePermissions.fromString("rw-------"));
            } else {
                // CAUTION If the underlying file system can not distinguish the owner's read permission from that of others,
                //         then the permission will apply to everybody, regardless of this value.
                jwksFile.setReadable(true, true);
                jwksFile.setWritable(true, true);
            }
        }

        // Output the public OKP JWK parameters only
        return jwk.toPublicJWK().toJSONString();
    }

    /**
     * See https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-eddsa
     *
     * @param jwk
     * @return
     * @throws com.nimbusds.jose.JOSEException
     */
    static boolean sign(OctetKeyPair jwk, String payload) throws com.nimbusds.jose.JOSEException {

        // Create the EdDSA signer
        JWSSigner signer = new Ed25519Signer(jwk);

        // Creates the JWS object with payload
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(jwk.getKeyID()).build(),
                new Payload(payload));

        // Compute the EdDSA signature
        jwsObject.sign(signer);

        // The recipient creates a verifier with the public EdDSA key
        return jwsObject.verify(new Ed25519Verifier(jwk.toPublicJWK()));
    }

}
