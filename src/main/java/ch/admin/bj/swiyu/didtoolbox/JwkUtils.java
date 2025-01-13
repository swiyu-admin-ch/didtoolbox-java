package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.*;
import java.text.ParseException;

/**
 * Simple proxy/wrapper to/of com.nimbusds.jose.jwk classes (https://connect2id.com/products/nimbus-jose-jwt)
 */
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

    /**
     * Generates a new key pair (in JWKS format) using standard EC digital signature algorithm EC P-256 DSA with SHA-256.
     * If jwksFile is supplied, the keys are exported in JWKS and PEM format.
     *
     * @param keyID
     * @param jwksFile
     * @return a new EC key pair in JWKS format
     * @throws IOException
     */
    static String generateEC(String keyID, File jwksFile) throws IOException {

        ECKey jwk = null;
        try {
            jwk = new ECKeyGenerator(Curve.P_256) // see https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-ec-signature
                    //.keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                    //.keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                    .keyID(keyID) // give the key a unique ID (optional)
                    //.issueTime(new Date()) // issued-at timestamp (optional)
                    .generate();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        if (jwksFile != null) {

            var jsonArray = new JsonArray();
            jsonArray.add(JsonParser.parseString(jwk.toJSONString()));
            var keys = new JsonObject();
            keys.add("keys", jsonArray);

            var w = new BufferedWriter(new FileWriter(new File(jwksFile.getPath() + ".json")));
            try {
                w.write(keys.toString());
                w.flush();
            } finally {
                w.close();
            }

            exportAsEcKeyToPem(jwk, jwksFile);

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
     * PEM export helper.
     *
     * @param jwk
     * @param jwksFile
     * @throws IOException
     */
    private static void exportAsEcKeyToPem(ECKey jwk, File jwksFile) throws IOException {
        PemWriter pemWriter = new PemWriter(new FileWriter(jwksFile));
        PemWriter pemWriterPub = new PemWriter(new FileWriter(new File(jwksFile.getPath() + ".pub")));
        try {

            var keyFactory = KeyFactory.getInstance("EC");

            AlgorithmParameters a = AlgorithmParameters.getInstance("EC");
            a.init(new ECGenParameterSpec("secp256k1"));
            ECParameterSpec parameterSpec = a.getParameterSpec(ECParameterSpec.class);
            PrivateKey privKey = keyFactory.generatePrivate(new ECPrivateKeySpec(jwk.getD().decodeToBigInteger(), parameterSpec));

            // as specified by https://www.rfc-editor.org/rfc/rfc5915
            pemWriter.writeObject(new PemObject("EC PRIVATE KEY", privKey.getEncoded()));
            pemWriter.flush();

            PublicKey pubKey = keyFactory.generatePublic(new ECPublicKeySpec(new ECPoint(jwk.getX().decodeToBigInteger(), jwk.getY().decodeToBigInteger()), parameterSpec));

            // as specified by https://www.rfc-editor.org/rfc/rfc5208
            pemWriterPub.writeObject(new PemObject("PUBLIC KEY", pubKey.getEncoded()));
            pemWriterPub.flush();

            ecPemSanityCheck(new File(jwksFile.getPath()), new File(jwksFile.getPath() + ".pub"));

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidParameterSpecException |
                 InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        } finally {
            pemWriter.close();
        }
    }

    /**
     * Helper for the PEM export.
     *
     * @param privatePemFile
     * @param publicPemFile
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    private static void ecPemSanityCheck(File privatePemFile, File publicPemFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PrivateKey privKey = PemUtils.getPrivateKey(PemUtils.parsePEMFile(privatePemFile), "EC");
        PublicKey publicKey = PemUtils.getPublicKey(PemUtils.parsePEMFile(publicPemFile), "EC");

        String msg = "hello world";
        byte[] data = msg.getBytes(StandardCharsets.UTF_8);

        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privKey);
        signature.update(data);

        signature.initVerify(publicKey);
        signature.update(data);
        signature.verify(data);

        if (!msg.equals(new String(data))) {
            throw new RuntimeException("exported key do not match");
        }
    }
}
