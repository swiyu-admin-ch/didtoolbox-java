package ch.admin.bj.swiyu.didtoolbox;

import io.ipfs.multibase.Base58;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

/**
 * Builds on top of {@link org.bouncycastle.crypto.signers.Ed25519Signer} by adding further useful helpers.
 */
class Ed25519SignerVerifier {

    byte[] signingKey = new byte[32];
    byte[] verifyingKey = new byte[32];

    Ed25519SignerVerifier() {

        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("Ed25519");
            //keyPairGen.initialize(NamedParameterSpec.ED25519, new SecureRandom(secretKey));
            keyPairGen.initialize(NamedParameterSpec.ED25519);

            KeyPair keyPair = keyPairGen.generateKeyPair();

            byte[] privateKey = keyPair.getPrivate().getEncoded();
            this.signingKey = Arrays.copyOfRange(privateKey, privateKey.length - 32, privateKey.length); // the last 32 bytes

            byte[] publicKey = keyPair.getPublic().getEncoded();
            this.verifyingKey = Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length); // the last 32 bytes

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * The constructor accepting keys in multibase base58btc format, e.g.
     * <p>
     * {@snippet lang = JSON:
     *     {
     *         "publicKeyMultibase": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
     *         "secretKeyMultibase": "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
     *     }
     *}
     *
     * @param privateKeyMultibase
     * @param publicKeyMultibase
     */
    Ed25519SignerVerifier(String privateKeyMultibase, String publicKeyMultibase) {

        var signingKey = Base58.decode(privateKeyMultibase.substring(1));
        var verifyingKey = Base58.decode(publicKeyMultibase.substring(1));

        ByteBuffer buff = ByteBuffer.allocate(32);
        buff.put(Arrays.copyOfRange(signingKey, signingKey.length - 32, signingKey.length));
        this.signingKey = buff.array();

        buff = ByteBuffer.allocate(32);
        buff.put(Arrays.copyOfRange(verifyingKey, verifyingKey.length - 32, verifyingKey.length));
        this.verifyingKey = buff.array();

        // sanity check
        if (!this.verify("hello world", this.signString("hello world"))) {
            throw new RuntimeException("keys do not match");
        }
    }

    /*
    public byte[] getSigningKey() {
        return signingKey;
    }
    */

    /**
     * The Java KeyStore (JKS) compliant constructor.
     *
     * @param jksFile
     * @param password
     * @param alias
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableEntryException
     */
    Ed25519SignerVerifier(InputStream jksFile, String password, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(jksFile, password.toCharArray()); // java.io.IOException: keystore password was incorrect

        //var entryPassword = new KeyStore.PasswordProtection(password.toCharArray());
        //KeyStore.Entry keyEntry = keyStore.getEntry(alias, entryPassword);

        var key = keyStore.getKey(alias, password.toCharArray()); // 34 bytes, may return null if the given alias does not exist or does not identify a key-related entry
        /*
        if key == null {
            throw
        }
         */
        byte[] privateKey = key.getEncoded(); // 48 bytes
        this.signingKey = Arrays.copyOfRange(privateKey, privateKey.length - 32, privateKey.length); // the last 32 bytes

        var cert = keyStore.getCertificate(alias); // may return null if the given alias does not exist or does not contain a certificate
        /*
        if cert == null {
            throw
        }
         */
        byte[] publicKey = cert.getPublicKey().getEncoded(); // 44 bytes
        this.verifyingKey = Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length); // the last 32 bytes
    }

    /**
     * The PEM file based constructor.
     *
     * @param privatePemFile
     * @param publicPemFile
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    Ed25519SignerVerifier(File privatePemFile, File publicPemFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        byte[] privatePemBytes = PemUtils.parsePEMFile(privatePemFile);
        PrivateKey privKey = PemUtils.getPrivateKeyEd25519(privatePemBytes);
        byte[] privateKey = privKey.getEncoded(); // 48 bytes
        this.signingKey = Arrays.copyOfRange(privateKey, privateKey.length - 32, privateKey.length); // the last 32 bytes

        byte[] publicPemBytes = PemUtils.parsePEMFile(publicPemFile);
        PublicKey pubKey = PemUtils.getPublicKeyEd25519(publicPemBytes);
        byte[] publicKey = pubKey.getEncoded(); // 44 bytes
        this.verifyingKey = Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length); // the last 32 bytes
    }

    /**
     * The encoding of an Ed25519 public key MUST start with the two-byte prefix 0xed01 (the varint expression of 0xed),
     * followed by the 32-byte public key data. The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
     * according to Section 2.4 Multibase (https://www.w3.org/TR/controller-document/#multibase-0),
     * and then prepended with the base-58-btc Multibase header (z).
     * <p>See https://www.w3.org/TR/controller-document/#Multikey
     *
     * @param verifyingKey
     * @return
     */
    static String buildVerificationKeyMultibase(byte[] verifyingKey) {

        ByteBuffer buff = ByteBuffer.allocate(34);
        // See https://github.com/multiformats/multicodec/blob/master/table.csv#L98
        buff.put((byte) 0xed); // Ed25519Pub/ed25519-pub is a draft code tagged "key" and described by: Ed25519 public key.
        buff.put((byte) 0x01);
        buff.put(Arrays.copyOfRange(verifyingKey, verifyingKey.length - 32, verifyingKey.length));
        return 'z' + Base58.encode(buff.array());
    }

    /**
     * According to https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020:
     * <p>The publicKeyMultibase property of the verification method MUST be a public key encoded according to [MULTICODEC] and formatted according to [MULTIBASE].
     * The multicodec encoding of a Ed25519 public key is the two-byte prefix 0xed01 followed by the 32-byte public key data.
     *
     * @return
     */
    String getVerificationKeyMultibase() {
        return buildVerificationKeyMultibase(this.verifyingKey);
    }

    byte[] signString(String message) {

        byte[] msg = message.getBytes(StandardCharsets.UTF_8);

        Ed25519PrivateKeyParameters secretKeyParameters = new Ed25519PrivateKeyParameters(this.signingKey, 0);
        var signer = new Ed25519Signer();
        signer.init(true, secretKeyParameters);
        signer.update(msg, 0, msg.length);

        return signer.generateSignature();
    }

    byte[] signBytes(byte[] message) {

        Ed25519PrivateKeyParameters secretKeyParameters = new Ed25519PrivateKeyParameters(this.signingKey, 0);
        var signer = new Ed25519Signer();
        signer.init(true, secretKeyParameters);
        signer.update(message, 0, message.length);

        return signer.generateSignature();
    }

    boolean verify(String message, byte[] signature) {

        Ed25519PublicKeyParameters publicKeyParameters = new Ed25519PublicKeyParameters(this.verifyingKey, 0);
        var verifier = new Ed25519Signer();
        verifier.init(false, publicKeyParameters);
        byte[] msg = message.getBytes(StandardCharsets.UTF_8);
        verifier.update(msg, 0, msg.length);

        return verifier.verifySignature(signature);

    }

    boolean verifyBytes(byte[] message, byte[] signature) {

        Ed25519PublicKeyParameters publicKeyParameters = new Ed25519PublicKeyParameters(this.verifyingKey, 0);
        var verifier = new Ed25519Signer();
        verifier.init(false, publicKeyParameters);
        verifier.update(message, 0, message.length);

        return verifier.verifySignature(signature);

    }
}
