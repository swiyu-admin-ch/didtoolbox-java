package ch.admin.bj.swiyu.didtoolbox;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class PemUtils {

    private PemUtils() {
    }

    /**
     * Loads a PEM key from the supplied file.
     *
     * @param pemFile to read PEM key from
     * @return the PEM key as byte array
     * @throws FileNotFoundException in case of inappropriate {@code pemFile} parameter value
     * @throws IOException           in case of a parse error
     */
    public static byte[] parsePEMFile(File pemFile) throws IOException {

        if (!pemFile.isFile() || !pemFile.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }
        return readPemObject(Files.newBufferedReader(pemFile.toPath()));
    }

    static byte[] readPemObject(Reader pemKeyReader) throws IOException {
        PemReader reader = new PemReader(pemKeyReader);
        PemObject pemObject = reader.readPemObject();
        byte[] content = pemObject.getContent();
        reader.close();
        return content;
    }

    static PublicKey getPublicKey(byte[] keyBytes, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance(algorithm);
        return factory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    static PrivateKey getPrivateKey(byte[] keyBytes, String algorithm) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory factory = KeyFactory.getInstance(algorithm);
        return factory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    static PublicKey getPublicKeyEd25519(byte[] encodedKey) throws InvalidKeySpecException {
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("Ed25519");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        return factory.generatePublic(new X509EncodedKeySpec(encodedKey));
    }

    public static String parsePEMFilePublicKeyEd25519Multibase(File pemFile) throws InvalidKeySpecException, IOException {

        PublicKey pubKey = PemUtils.getPublicKeyEd25519(parsePEMFile(pemFile));

        // may throw IllegalArgumentException if the supplied public key does not support encoding
        return Ed25519Utils.encodeMultibase(pubKey);
    }

    static String parsePEMPublicKeyEd25519Multibase(String pemPublicKey) throws InvalidKeySpecException, IOException {

        File tempFile = File.createTempFile("mypublickey", ".pem");
        tempFile.deleteOnExit();

        Writer w = Files.newBufferedWriter(tempFile.toPath());
        try {
            w.write(pemPublicKey);
            w.flush();
        } finally {
            w.close();
        }

        return parsePEMFilePublicKeyEd25519Multibase(tempFile);
    }

    static PrivateKey getPrivateKeyEd25519(byte[] encodedKey) throws InvalidKeySpecException {
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("Ed25519");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
        return factory.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
    }

    static PublicKey readPublicKeyFromFile(String filepath, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = parsePEMFile(new File(filepath));
        return getPublicKey(bytes, algorithm);
    }

    static PrivateKey readPrivateKeyFromFile(String filepath, String algorithm) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] bytes = parsePEMFile(new File(filepath));
        return getPrivateKey(bytes, algorithm);
    }

}