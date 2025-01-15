package ch.admin.bj.swiyu.didtoolbox;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class PemUtils {

    private PemUtils() {
    }

    /**
     * @param pemFile
     * @return
     * @throws IOException in case of a parse error.
     */
    static byte[] parsePEMFile(File pemFile) throws IOException {
        if (!pemFile.isFile() || !pemFile.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }
        PemReader reader = new PemReader(new FileReader(pemFile));
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
            throw new RuntimeException(e);
        }
        return factory.generatePublic(new X509EncodedKeySpec(encodedKey));
    }

    static PrivateKey getPrivateKeyEd25519(byte[] encodedKey) throws InvalidKeySpecException {
        KeyFactory factory = null;
        try {
            factory = KeyFactory.getInstance("Ed25519");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
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