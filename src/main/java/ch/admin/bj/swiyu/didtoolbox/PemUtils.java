package ch.admin.bj.swiyu.didtoolbox;

import io.ipfs.multibase.Base58;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

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

    static String parsePEMFilePublicKeyEd25519Multibase(File pemFile) throws InvalidKeySpecException, IOException {

        PublicKey pubKey = PemUtils.getPublicKeyEd25519(parsePEMFile(pemFile));
        byte[] publicKey = pubKey.getEncoded(); // 44 bytes
        var verifyingKey = Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length); // the last 32 bytes

        ByteBuffer buff = ByteBuffer.allocate(34);
        // See https://github.com/multiformats/multicodec/blob/master/table.csv#L98
        buff.put((byte) 0xed); // Ed25519Pub/ed25519-pub is a draft code tagged "key" and described by: Ed25519 public key.
        buff.put((byte) 0x01);
        buff.put(Arrays.copyOfRange(verifyingKey, verifyingKey.length - 32, verifyingKey.length));

        return 'z' + Base58.encode(buff.array());
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