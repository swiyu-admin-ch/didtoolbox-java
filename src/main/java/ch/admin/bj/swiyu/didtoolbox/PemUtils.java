package ch.admin.bj.swiyu.didtoolbox;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
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

    static byte[] parsePEMFile(File pemFile) throws IOException {

        if (!pemFile.isFile() || !pemFile.exists()) {
            throw new FileNotFoundException(String.format("The file '%s' doesn't exist.", pemFile.getAbsolutePath()));
        }
        return readPemObject(new FileReader(pemFile));
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
            throw new RuntimeException(e);
        }
        return factory.generatePublic(new X509EncodedKeySpec(encodedKey));
    }

    static String parsePEMFilePublicKeyEd25519Multibase(File pemFile) throws InvalidKeySpecException, IOException {

        PublicKey pubKey = PemUtils.getPublicKeyEd25519(parsePEMFile(pemFile));
        byte[] publicKeyEncoded = pubKey.getEncoded(); // 44 bytes
        if (publicKeyEncoded == null) {
            throw new RuntimeException("The public key does not support encoding");
        }

        return Ed25519Utils.encodeMultibase(publicKeyEncoded);
    }

    static String parsePEMPublicKeyEd25519Multibase(String pemPublicKey) throws InvalidKeySpecException, IOException {

        File tempFile = File.createTempFile("mypublickey", ".pem");
        tempFile.deleteOnExit();

        Writer w = new BufferedWriter(new FileWriter(tempFile));
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