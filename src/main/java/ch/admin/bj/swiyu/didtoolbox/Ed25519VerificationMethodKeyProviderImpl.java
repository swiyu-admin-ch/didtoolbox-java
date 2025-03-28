package ch.admin.bj.swiyu.didtoolbox;

import io.ipfs.multibase.Base58;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

/**
 * The {@link Ed25519VerificationMethodKeyProviderImpl} class is a {@link VerificationMethodKeyProvider} implementation used to generate pairs of
 * public and private keys for the Ed25519 algorithm (or loading them from the file system). Such key pair is used then
 * for the purpose of <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log creation.
 * Furthermore, it also plays an essential role while <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">creating data integrity proof</a>.
 * It builds extensively on top of {@link org.bouncycastle.crypto.signers.Ed25519Signer} and introduces various useful helpers.
 * <p>
 * It is predominantly intended to be used within the {@link TdwCreator.TdwCreatorBuilder#verificationMethodKeyProvider} method
 * prior to a {@link TdwCreator#create(URL)} call.
 * <p>
 * Thanks to the following methods, it is also capable of loading an already existing key material from the file system:
 * <ul>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(File, File)} for loading the update (Ed25519) key from
 * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> files</li>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(InputStream, String, String)} for loading the update (Ed25519) key from Java KeyStore (JKS) files</li>
 * </ul>
 *
 * @see KeyPairGenerator
 * @see org.bouncycastle.crypto.signers.Ed25519Signer
 */
public class Ed25519VerificationMethodKeyProviderImpl implements VerificationMethodKeyProvider {

    byte[] signingKey = new byte[32];
    byte[] verifyingKey = new byte[32];
    private KeyPair keyPair;

    /**
     * @see KeyPairGenerator
     */
    Ed25519VerificationMethodKeyProviderImpl() {

        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("Ed25519");
            //keyPairGen.initialize(NamedParameterSpec.ED25519, new SecureRandom(secretKey));
            keyPairGen.initialize(NamedParameterSpec.ED25519);

            keyPair = keyPairGen.generateKeyPair();

            byte[] privateKey = keyPair.getPrivate().getEncoded(); // may return null
            this.signingKey = Arrays.copyOfRange(privateKey, privateKey.length - 32, privateKey.length); // the last 32 bytes

            byte[] publicKey = keyPair.getPublic().getEncoded();
            this.verifyingKey = Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length); // the last 32 bytes

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Yet another {@link Ed25519VerificationMethodKeyProviderImpl} constructor accepting keys in multibase base58btc format, e.g.
     * <p>
     * {@snippet lang = JSON:
     *     {
     *         "publicKeyMultibase": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
     *         "secretKeyMultibase": "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq"
     *     }
     *}
     * <p>
     * CAUTION It is assumed the keys do really match. Otherwise, {@link RuntimeException} is thrown.
     *
     * @param privateKeyMultibase the base58-encoded string to decode as private Ed25519 key
     * @param publicKeyMultibase  the base58-encoded string to decode as public Ed25519 key
     */
    public Ed25519VerificationMethodKeyProviderImpl(String privateKeyMultibase, String publicKeyMultibase) {

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

    /**
     * The Java KeyStore (JKS) compliant {@link Ed25519VerificationMethodKeyProviderImpl} constructor.
     *
     * @param jksFile  the input stream from which the keystore is loaded, or null
     * @param password the password used to check the integrity of the keystore, the password used to unlock the keystore, or null
     * @param alias    the alias name the key is associated with
     * @throws KeyStoreException           ...
     * @throws CertificateException        ...
     * @throws IOException                 ...
     * @throws NoSuchAlgorithmException    ...
     * @throws UnrecoverableEntryException ...
     * @see KeyStore#load(InputStream, char[])
     */
    public Ed25519VerificationMethodKeyProviderImpl(InputStream jksFile, String password, String alias) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(jksFile, password.toCharArray()); // java.io.IOException: keystore password was incorrect

        //var entryPassword = new KeyStore.PasswordProtection(password.toCharArray());
        //KeyStore.Entry keyEntry = keyStore.getEntry(alias, entryPassword);

        Key key = keyStore.getKey(alias, password.toCharArray()); // 34 bytes, may return null if the given alias does not exist or does not identify a key-related entry
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

        // sanity check
        if (!this.verify("hello world", this.signString("hello world"))) {
            throw new RuntimeException("keys do not match");
        }
    }

    public Ed25519VerificationMethodKeyProviderImpl(KeyStore keyStore, String alias, String password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {

        Key key = keyStore.getKey(alias, password.toCharArray()); // 34 bytes, may return null if the given alias does not exist or does not identify a key-related entry
        byte[] privateKey = key.getEncoded(); // 48 bytes
        this.signingKey = Arrays.copyOfRange(privateKey, privateKey.length - 32, privateKey.length); // the last 32 bytes

        // throws KeyStoreException – if the keystore has not been initialized (loaded).
        byte[] publicKey = keyStore.getCertificate(alias).getPublicKey().getEncoded(); // 44 bytes;
        this.verifyingKey = Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length); // the last 32 bytes

        // sanity check
        if (!this.verify("hello world", this.signString("hello world"))) {
            throw new RuntimeException("keys do not match");
        }
    }

    /**
     * The <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> file based {@link Ed25519VerificationMethodKeyProviderImpl} constructor.
     * <p>
     * CAUTION It is assumed the keys do really match. Otherwise, {@link RuntimeException} is thrown.
     *
     * @param privatePemFile file to load a private Ed25519 key from. It is assumed to be encoded according to the PKCS #8 standard.
     * @param publicPemFile  file to load a public Ed25519 key from. It is assumed to be encoded according to the X.509 standard.
     * @throws IOException             in case of a parse error.
     * @throws InvalidKeySpecException if any of the given key specifications is inappropriate for its key factory to produce a key.
     */
    public Ed25519VerificationMethodKeyProviderImpl(File privatePemFile, File publicPemFile) throws IOException, InvalidKeySpecException {

        byte[] privatePemBytes = PemUtils.parsePEMFile(privatePemFile);
        PrivateKey privKey = PemUtils.getPrivateKeyEd25519(privatePemBytes);
        byte[] privateKey = privKey.getEncoded(); // 48 bytes
        this.signingKey = Arrays.copyOfRange(privateKey, privateKey.length - 32, privateKey.length); // the last 32 bytes

        byte[] publicPemBytes = PemUtils.parsePEMFile(publicPemFile);
        PublicKey pubKey = PemUtils.getPublicKeyEd25519(publicPemBytes);
        byte[] publicKey = pubKey.getEncoded(); // 44 bytes
        this.verifyingKey = Arrays.copyOfRange(publicKey, publicKey.length - 32, publicKey.length); // the last 32 bytes

        keyPair = new KeyPair(pubKey, privKey);

        // sanity check
        if (!this.verify("hello world", this.signString("hello world"))) {
            throw new RuntimeException("keys do not match");
        }
    }

    /**
     * Yet another "hybrid" {@link Ed25519VerificationMethodKeyProviderImpl} constructor accepting keys in various formats.
     * <p>
     * CAUTION It is assumed the keys do really match. Otherwise, {@link RuntimeException} is thrown.
     *
     * @param privatePemFile     file to load a private Ed25519 key from. It is assumed to be encoded according to the PKCS #8 standard.
     * @param publicKeyMultibase the base58-encoded string to decode as public Ed25519 key.
     * @throws IOException             in case of a parse error.
     * @throws InvalidKeySpecException if any of the given key specifications is inappropriate for its key factory to produce a key.
     */
    public Ed25519VerificationMethodKeyProviderImpl(File privatePemFile, String publicKeyMultibase) throws IOException, InvalidKeySpecException {

        byte[] privatePemBytes = PemUtils.parsePEMFile(privatePemFile);
        PrivateKey privKey = PemUtils.getPrivateKeyEd25519(privatePemBytes);
        byte[] privateKey = privKey.getEncoded(); // 48 bytes
        this.signingKey = Arrays.copyOfRange(privateKey, privateKey.length - 32, privateKey.length); // the last 32 bytes

        var verifyingKey = Base58.decode(publicKeyMultibase.substring(1));

        ByteBuffer buff = ByteBuffer.allocate(32);
        buff = ByteBuffer.allocate(32);
        buff.put(Arrays.copyOfRange(verifyingKey, verifyingKey.length - 32, verifyingKey.length));
        this.verifyingKey = buff.array();

        // sanity check
        if (!this.verify("hello world", this.signString("hello world"))) {
            throw new RuntimeException("keys do not match");
        }
    }

    /**
     * The encoding of an Ed25519 public key MUST start with the two-byte prefix 0xed01 (the varint expression of 0xed),
     * followed by the 32-byte public key data. The resulting 34-byte value MUST then be encoded using the base-58-btc alphabet,
     * and then prepended with the <a href="https://www.w3.org/TR/controller-document/#multibase-0">base-58-btc Multibase header (z)</a>.
     * <p>
     * See <a href="https://www.w3.org/TR/controller-document/#Multikey">Multikey</a>
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
     * @param file to store the key
     * @throws IOException
     */
    void writePrivateKeyAsPem(File file) throws IOException {

        if (keyPair == null) {
            throw new RuntimeException("This instance features no self-generated key pair.");
        }

        var key = keyPair.getPrivate();
        PemWriter pemWriter = new PemWriter(new FileWriter(file));
        try {
            pemWriter.writeObject(new PemObject("PRIVATE KEY", key.getEncoded()));
        } finally {
            pemWriter.close();
        }
        // A private key file should always get appropriate file permissions, if feasible
        PosixFileAttributeView posixFileAttributeView = Files.getFileAttributeView(file.toPath(), PosixFileAttributeView.class);
        if (!System.getProperty("os.name").toLowerCase().contains("win") && posixFileAttributeView != null) {
            Files.setPosixFilePermissions(file.toPath(), PosixFilePermissions.fromString("rw-------"));
        } else {
            // CAUTION If the underlying file system can not distinguish the owner's read permission from that of others,
            //         then the permission will apply to everybody, regardless of this value.
            file.setReadable(true, true);
            file.setWritable(true, true);
        }
    }

    /**
     * @param file to store the key
     * @throws IOException
     */
    void writePublicKeyAsPem(File file) throws IOException {

        if (keyPair == null) {
            throw new RuntimeException("This instance features no self-generated key pair.");
        }

        var key = keyPair.getPublic();
        PemWriter pemWriter = new PemWriter(new FileWriter(file));
        try {
            pemWriter.writeObject(new PemObject("PUBLIC KEY", key.getEncoded()));
        } finally {
            pemWriter.close();
        }
    }

    /**
     * This {@link VerificationMethodKeyProvider} interface method implementation is done w.r.t.
     * <a href="https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020">d25519verificationkey2020</a>:
     * <pre>
     * The publicKeyMultibase property of the verification method MUST be a public key encoded according to [MULTICODEC] and formatted according to [MULTIBASE].
     * The multicodec encoding of a Ed25519 public key is the two-byte prefix 0xed01 followed by the 32-byte public key data.
     * </pre>
     *
     * @return public verification key in multibase format.
     */
    public String getVerificationKeyMultibase() {
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

    /**
     * The {@link VerificationMethodKeyProvider} interface method implementation using Ed25519 algorithm.
     *
     * @param message to sign
     * @return signed message
     */
    public byte[] generateSignature(byte[] message) {

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
