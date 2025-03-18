package ch.admin.bj.swiyu.didtoolbox;

import com.google.gson.JsonParser;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

/**
 * The {@link JwkUtils} is a simple helper for the purpose of <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">JWKS</a>
 * key pair generation
 */
public class JwkUtils {

    private JwkUtils() {
    }

    /**
     * Loads a public EC P-256 key from the specified PEM file and returns its JWK JSON representation
     *
     * @param ecPublicPemFile the EC P-256 public key in PEM format
     * @param kid             the ID (kid) of the JWK that can be used to match this key
     * @return JSON object string representation of the public JWK
     * @throws IOException             if the file couldn't be read
     * @throws InvalidKeySpecException if the given key specification is inappropriate for the EC key factory to produce a public key
     */
    public static String loadECPublicJWKasJSON(File ecPublicPemFile, String kid) throws IOException, InvalidKeySpecException {
        if (!ecPublicPemFile.isFile() || !ecPublicPemFile.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", ecPublicPemFile.getAbsolutePath()));
        }

        // see https://connect2id.com/products/nimbus-jose-jwt/examples/pem-encoded-objects

        ECPublicKey publicKey = null;
        try {
            publicKey = (ECPublicKey) PemUtils.getPublicKey(PemUtils.parsePEMFile(ecPublicPemFile), "EC");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return (new ECKey.Builder(Curve.P_256, publicKey)).keyID(kid).build().toPublicJWK().toJSONString();
    }

    /**
     * Generates a new key pair (in <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">JWKS</a> format)
     * using standard digital signature algorithm
     * <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-3.4">ECDSA using P-256 curve and SHA-256 hash function</a>.
     * If {@code keyPairPemFile} is supplied, the key pair is exported in
     * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format.
     *
     * @param kid            the ID of the JWK, that can be used to match a specific key
     * @param keyPairPemFile if not {@code null}, the file where a generated key pair will be stored
     *                       (in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format)
     * @param forceOverwrite the flag controlling whether the existing PEM files should be overwritten or not
     * @return a new public EC JWK (in JSON format).
     * @throws IOException if persisting a key pair fails
     */
    public static String generatePublicEC256(String kid, File keyPairPemFile, boolean forceOverwrite) throws IOException {

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        keyPairGenerator.initialize(256);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair); // CAUTION The whole key pair is expected to be written here, not only the private key
        }
        String keyPairPem = stringWriter.toString();

        stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(keyPair.getPublic());
        }
        String publicKeyPem = stringWriter.toString();

        ECKey publicJwk = null;
        try {
            // CAUTION By using com.nimbusds.jose.jwk.gen.ECKeyGenerator (see https://connect2id.com/products/nimbus-jose-jwt/examples/jws-with-ec-signature)
            //         to create a com.nimbusds.jose.jwk.JWK object you may end up having incomplete EC PRIVATE KEY export later on.
            publicJwk = JWK.parseFromPEMEncodedObjects(publicKeyPem).toECKey();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        var publicJwkJsonObject = JsonParser.parseString(publicJwk.toJSONString()).getAsJsonObject();
        publicJwkJsonObject.addProperty("kid", kid);

        if (keyPairPemFile != null) {

            if (!keyPairPemFile.exists() || forceOverwrite) {

                Writer w = new BufferedWriter(new FileWriter(keyPairPemFile));
                try {
                    w.write(keyPairPem);
                    w.flush();
                } finally {
                    w.close();
                }

                exportEcPublicKeyToPem(publicJwk, keyPairPemFile);

                // A private key file should always get appropriate file permissions, if feasible
                PosixFileAttributeView posixFileAttributeView = Files.getFileAttributeView(keyPairPemFile.toPath(), PosixFileAttributeView.class);
                if (!System.getProperty("os.name").toLowerCase().contains("win") && posixFileAttributeView != null) {
                    Files.setPosixFilePermissions(keyPairPemFile.toPath(), PosixFilePermissions.fromString("rw-------"));
                } else {
                    // CAUTION If the underlying file system can not distinguish the owner's read permission from that of others,
                    //         then the permission will apply to everybody, regardless of this value.
                    keyPairPemFile.setReadable(true, true);
                    keyPairPemFile.setWritable(true, true);
                }

            } else {
                throw new IOException("The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged: " + keyPairPemFile.getPath());
            }
        }

        return publicJwkJsonObject.toString();
    }

    /**
     * PEM export helper.
     *
     * @param jwk
     * @param keyPairPemFile
     * @throws IOException
     */
    private static void exportEcPublicKeyToPem(ECKey jwk, File keyPairPemFile) throws IOException {
        JcaPEMWriter pemWriterPub = new JcaPEMWriter(new FileWriter(keyPairPemFile.getPath() + ".pub"));
        try {
            // as specified by https://www.rfc-editor.org/rfc/rfc5208
            pemWriterPub.writeObject(new PemObject("PUBLIC KEY", jwk.toPublicKey().getEncoded()));
            pemWriterPub.flush();

            ecPemSanityCheck(new File(keyPairPemFile.getPath()), new File(keyPairPemFile.getPath() + ".pub"));

        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidParameterSpecException |
                 InvalidKeyException | SignatureException | NoSuchProviderException | JOSEException e) {
            throw new RuntimeException(e);
        } finally {
            pemWriterPub.close();
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
    static void ecPemSanityCheck(File privatePemFile, File publicPemFile) throws IOException, InvalidKeySpecException,
            NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidParameterSpecException, NoSuchProviderException, JOSEException {

        ECPrivateKey privKey = (ECPrivateKey) JWK.parseFromPEMEncodedObjects(Files.readString(privatePemFile.toPath())).toECKey().toPrivateKey();
        ECPublicKey publicKey = (ECPublicKey) PemUtils.getPublicKey(PemUtils.parsePEMFile(publicPemFile), "EC");

        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).build(),
                new Payload("hello world"));
        jwsObject.sign(new ECDSASigner(privKey));

        //String s = jwsObject.serialize(); // compact form

        if (!jwsObject.verify(new ECDSAVerifier(publicKey)) || (!"hello world".equals(jwsObject.getPayload().toString()))) {
            throw new RuntimeException("exported key do not match");
        }
    }
}
