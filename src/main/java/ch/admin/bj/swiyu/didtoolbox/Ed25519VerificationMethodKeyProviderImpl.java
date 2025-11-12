package ch.admin.bj.swiyu.didtoolbox;

import io.ipfs.multibase.Base58;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import java.util.Random;
import java.util.Set;

/**
 * The {@link Ed25519VerificationMethodKeyProviderImpl} class is a {@link VerificationMethodKeyProvider} implementation used to generate pairs of
 * public and private keys for the Ed25519 algorithm (or loading them from the file system). Such key pair is then used
 * for the purpose of <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log creation.
 * Furthermore, it also plays an essential role while <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">creating data integrity proof</a>.
 * It builds on top of {@link java.security} and introduces various useful helpers.
 * <p>
 * It is predominantly intended to be used within a:
 * <ul>
 * <li> {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext.DidLogCreatorContextBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} method
 * (prior to a {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext#create(URL)} call)</li>
 * <li>{@link ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext.DidLogUpdaterContextBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} method
 * (prior to a {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext#update(String)} call).</li>
 * </ul>
 * <p>
 * Thanks to the following constructor(s), it is also capable of loading an already existing key material from the file system:
 * <ul>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(Reader, Reader)} for loading the update (Ed25519) key from
 * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> files</li>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(InputStream, String, String, String)} for loading the update (Ed25519) key from Java KeyStore (JKS) files</li>
 * </ul>
 */
public class Ed25519VerificationMethodKeyProviderImpl implements VerificationMethodKeyProvider {

    final private static String DEFAULT_JCE_PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected final KeyPair keyPair;
    protected Provider provider = Security.getProvider(DEFAULT_JCE_PROVIDER_NAME);

    /**
     * The explicit constructor featuring an <code>Ed25519</code> {@link KeyPair} object.
     * It fails (with {@link IllegalArgumentException} thrown) if a supplied {@link KeyPair} object is either <code>null</code> or invalid for whatever reason
     * e.g. invalid encoding, wrong length, uninitialized, private/public key mismatch etc.
     * <p>
     * The (default) JCE provider remains {@link BouncyCastleProvider}.
     * <p>
     * CAUTION It is assumed the keys do really match. Otherwise, {@link IllegalArgumentException} is thrown.
     */
    public Ed25519VerificationMethodKeyProviderImpl(KeyPair ed25519KeyPair) {

        if (ed25519KeyPair == null) {
            throw new IllegalArgumentException("A valid key pair expected, instead of null");
        }

        this.keyPair = ed25519KeyPair;

        sanityCheck(this);
    }

    protected Ed25519VerificationMethodKeyProviderImpl(KeyPair ed25519KeyPair, Provider provider) {

        if (ed25519KeyPair == null) {
            throw new IllegalArgumentException("Valid key pair expected, instead of null");
        }

        this.keyPair = ed25519KeyPair;

        if (provider != null) {
            this.provider = provider;
        }

        if (this.provider == null) {
            throw new IllegalArgumentException("No default JCE provider installed: " + DEFAULT_JCE_PROVIDER_NAME);
        }

        sanityCheck(this);
    }

    /**
     * The copy constructor.
     */
    private Ed25519VerificationMethodKeyProviderImpl(Ed25519VerificationMethodKeyProviderImpl obj) {
        this(obj.keyPair, obj.provider);
        sanityCheck(this);
    }

    /**
     * @see KeyPairGenerator
     */
    public Ed25519VerificationMethodKeyProviderImpl() {

        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("Ed25519");
            //keyPairGen.initialize(NamedParameterSpec.ED25519, new SecureRandom(secretKey));
            keyPairGen.initialize(NamedParameterSpec.ED25519);

            this.keyPair = keyPairGen.generateKeyPair();

        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * The Java KeyStore (type: PKCS12) compliant {@link Ed25519VerificationMethodKeyProviderImpl} constructor.
     *
     * @param jksFile     the input stream from which the keystore is loaded, or null
     * @param password    the password used to check the integrity of the keystore, the password used to unlock the keystore, or null
     * @param alias       the alias name the key is associated with
     * @param keyPassword the password for recovering the key, or {@code null} if not required
     * @throws KeyStoreException           ...
     * @throws CertificateException        ...
     * @throws IOException                 ...
     * @throws NoSuchAlgorithmException    ...
     * @throws UnrecoverableEntryException ...
     * @throws KeyException                ...
     * @see KeyStore#load(InputStream, char[])
     */
    public Ed25519VerificationMethodKeyProviderImpl(InputStream jksFile, String password, String alias, String keyPassword)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyException {

        // CAUTION Calling KeyStore.getInstance("JKS") may cause:
        //         "java.security.NoSuchAlgorithmException: no such algorithm: EdDSA for provider SUN"
        KeyStore keyStore = KeyStore.getInstance("PKCS12", this.provider);
        char[] pass = null;
        if (password != null) {
            pass = password.toCharArray();
        }
        keyStore.load(jksFile, pass); // java.io.IOException: keystore password was incorrect

        // CAUTION Flexible constructors is a preview feature and is disabled by default. (use --enable-preview to enable flexible constructors)
        //this(createFromKeyStore(keyStore, alias, keyPassword));

        var obj = createFromKeyStore(keyStore, alias, keyPassword);
        this.keyPair = obj.keyPair;
        this.provider = obj.provider;
    }

    /**
     * The KeyStore-compliant {@link Ed25519VerificationMethodKeyProviderImpl} constructor.
     *
     * @param keyStore the {@link KeyStore} object (already loaded)
     * @param alias    the alias name the key is associated with
     * @param password the password for recovering the key, or {@code null} if not required
     * @throws KeyStoreException           ...
     * @throws NoSuchAlgorithmException    ...
     * @throws UnrecoverableEntryException ...
     * @throws KeyException                ...
     */
    public Ed25519VerificationMethodKeyProviderImpl(KeyStore keyStore, String alias, String password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyException {

        this(createFromKeyStore(keyStore, alias, password));
    }

    /**
     * The <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> file based {@link Ed25519VerificationMethodKeyProviderImpl} constructor.
     * <p>
     * CAUTION It is assumed the keys do really match. Otherwise, {@link IllegalArgumentException} is thrown.
     *
     * @param privatePemFile file to load a private Ed25519 key from. It is assumed to be encoded according to the PKCS #8 standard.
     * @param publicPemFile  file to load a public Ed25519 key from. It is assumed to be encoded according to the X.509 standard.
     * @throws IOException             in case of a parse error.
     * @throws InvalidKeySpecException if any of the given key specifications is inappropriate for its key factory to produce a key.
     * @deprecated use {@link #Ed25519VerificationMethodKeyProviderImpl(Reader, Reader)} instead.
     */
    @Deprecated
    public Ed25519VerificationMethodKeyProviderImpl(File privatePemFile, File publicPemFile) throws IOException, InvalidKeySpecException {
        this(Files.newBufferedReader(privatePemFile.toPath()),
                Files.newBufferedReader(publicPemFile.toPath()));
    }

    /**
     * The {@link Reader}-based {@link Ed25519VerificationMethodKeyProviderImpl} constructor
     * accepting keys in <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> format from various sources.
     * <p>
     * CAUTION It is assumed the keys do really match. Otherwise, {@link IllegalArgumentException} is thrown.
     *
     * @param privateKeyReader reader to load a private Ed25519 key from. It is assumed to be encoded according to the PKCS #8 standard.
     * @param publicKeyReader  reader to load a public Ed25519 key from. It is assumed to be encoded according to the X.509 standard.
     * @throws IOException             in case of a parse error.
     * @throws InvalidKeySpecException if any of the given key specifications is inappropriate for its key factory to produce a key.
     */
    public Ed25519VerificationMethodKeyProviderImpl(Reader privateKeyReader, Reader publicKeyReader) throws IOException, InvalidKeySpecException {
        byte[] privatePemBytes = PemUtils.readPemObject(privateKeyReader);
        PrivateKey privKey = PemUtils.getPrivateKeyEd25519(privatePemBytes);

        byte[] publicPemBytes = PemUtils.readPemObject(publicKeyReader);
        PublicKey pubKey = PemUtils.getPublicKeyEd25519(publicPemBytes);

        this.keyPair = new KeyPair(pubKey, privKey);

        sanityCheck(this);
    }

    /**
     * Yet another "hybrid" {@link Ed25519VerificationMethodKeyProviderImpl} constructor accepting keys in various formats.
     * <p>
     * CAUTION It is assumed the keys do really match. Otherwise, {@link IllegalArgumentException} is thrown.
     *
     * @param privatePemFile     file to load a private Ed25519 key from. It is assumed to be encoded according to the PKCS #8 standard.
     * @param publicKeyMultibase the base58-encoded string to decode as public Ed25519 key.
     * @throws IOException             in case of a parse error.
     * @throws InvalidKeySpecException if any of the given key specifications is inappropriate for its key factory to produce a key.
     * @deprecated use {@link #Ed25519VerificationMethodKeyProviderImpl(Reader, String)} instead.
     */
    @Deprecated
    public Ed25519VerificationMethodKeyProviderImpl(File privatePemFile, String publicKeyMultibase)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        this(Files.newBufferedReader(privatePemFile.toPath()), publicKeyMultibase);
    }

    /**
     * Yet another "hybrid" {@link Ed25519VerificationMethodKeyProviderImpl} constructor accepting keys in various formats and from various sources.
     * <p>
     * CAUTION It is assumed the keys do really match. Otherwise, {@link IllegalArgumentException} is thrown.
     *
     * @param privateKeyReader   reader to load a private Ed25519 key from. It is assumed to be encoded according to the PKCS #8 standard.
     * @param publicKeyMultibase the base58-encoded string to decode as public Ed25519 key.
     * @throws IOException             in case of a parse error.
     * @throws InvalidKeySpecException if any of the given key specifications is inappropriate for its key factory to produce a key.
     */
    public Ed25519VerificationMethodKeyProviderImpl(Reader privateKeyReader, String publicKeyMultibase)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {

        PrivateKey privKey = PemUtils.getPrivateKeyEd25519(PemUtils.readPemObject(privateKeyReader));

        var verifyingKey = Base58.decode(publicKeyMultibase.substring(1));
        ByteBuffer buff = ByteBuffer.allocate(32);
        var length = verifyingKey.length;
        buff.put(Arrays.copyOfRange(verifyingKey, length - 32, length));
        var pubKey = Ed25519Utils.toPublicKey(buff.array());

        this.keyPair = new KeyPair(pubKey, privKey);

        sanityCheck(this);
    }

    /**
     * Yet another static helper. Self-explanatory.
     *
     * @param keyStore the {@link KeyStore} object (already loaded)
     * @param alias    the alias name the key is associated with
     * @param password the password for recovering the key, or {@code null} if not required
     * @throws KeyStoreException           ...
     * @throws NoSuchAlgorithmException    ...
     * @throws UnrecoverableEntryException ...
     * @throws KeyException                ...
     */
    private static Ed25519VerificationMethodKeyProviderImpl createFromKeyStore(KeyStore keyStore, String alias, String password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyException {

        if (!keyStore.isKeyEntry(alias)) {
            throw new KeyException("The alias does not exist or does not identify a key-related entry: " + alias);
        }

        /* KeyStore#getKey throws:
        KeyStoreException – if the keystore has not been initialized (loaded).
        NoSuchAlgorithmException – if the algorithm for recovering the key cannot be found
        UnrecoverableKeyException – if the key cannot be recovered (e.g., the given password is wrong).
         */
        PrivateKey key;
        if (password != null) {
            key = (PrivateKey) keyStore.getKey(alias, password.toCharArray()); // 34 bytes, may return null if the given alias does not exist or does not identify a key-related entry
        } else {
            key = (PrivateKey) keyStore.getKey(alias, null); // 34 bytes, may return null if the given alias does not exist or does not identify a key-related entry
        }

        if (key == null) {
            throw new KeyException("The alias does not exist or does not identify a key-related entry: " + alias);
        }

        // throws KeyStoreException – if the keystore has not been initialized (loaded)
        var cert = keyStore.getCertificate(alias); // may return null if the given alias does not exist or does not contain a certificate
        if (cert == null) {
            throw new KeyException("The alias does not exist or does not contain a certificate: " + alias);
        }

        var publicKey = cert.getPublicKey();

        return new Ed25519VerificationMethodKeyProviderImpl(new KeyPair(publicKey, key), keyStore.getProvider());
    }

    /**
     * The private/public keys (supplied within {@link #keyPair}) should match. Otherwise, {@link IllegalArgumentException} is thrown.
     */
    protected static void sanityCheck(Ed25519VerificationMethodKeyProviderImpl impl) {

        // alphanumerical chars falls within  ['0':'z'] range with...
        var generatedString = new Random().ints(48, 122 + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97)) // ...with two gaps inbetween
                .limit(1024) // the higher, the better
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        if (!impl.verify(generatedString.getBytes(StandardCharsets.UTF_8), impl.generateSignature(generatedString.getBytes(StandardCharsets.UTF_8)))) {
            throw new IllegalArgumentException("supplied keys do not match");
        }
    }

    /**
     * CAUTION The method does not ensure that the private key file access is restricted to the current user only.
     *
     * @param file to store the key
     * @throws IOException
     */
    void writePrivateKeyAsPem(File file) throws IOException {

        var privateKeyEncoded = this.keyPair.getPrivate().getEncoded();
        if (privateKeyEncoded == null) {
            throw new IllegalArgumentException("The key pair features a private key that does not support encoding");
        }
        PemWriter pemWriter = new PemWriter(Files.newBufferedWriter(file.toPath()));
        try {
            pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKeyEncoded));
        } finally {
            pemWriter.close();
        }
    }

    /**
     * @param file to store the key
     * @throws IOException
     */
    public void writePublicKeyAsPem(File file) throws IOException {

        var publicKeyEncoded = this.keyPair.getPublic().getEncoded();
        if (publicKeyEncoded == null) {
            throw new IllegalArgumentException("The key pair features a public key that does not support encoding");
        }
        PemWriter pemWriter = new PemWriter(Files.newBufferedWriter(file.toPath()));
        try {
            pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKeyEncoded));
        } finally {
            pemWriter.close();
        }
    }

    /**
     * This {@link VerificationMethodKeyProvider} interface method implementation is done w.r.t.
     * <a href="https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020">Ed25519verificationkey2020</a>:
     * <pre>
     * The publicKeyMultibase property of the verification method MUST be a public key encoded according to [MULTICODEC] and formatted according to [MULTIBASE].
     * The multicodec encoding of a Ed25519 public key is the two-byte prefix 0xed01 followed by the 32-byte public key data.
     * </pre>
     *
     * @return public verification key in multibase format.
     */
    @Override
    public String getVerificationKeyMultibase() {
        // may throw IllegalArgumentException if the supplied public key does not support encoding
        return Ed25519Utils.encodeMultibase(this.keyPair.getPublic());
    }

    /**
     * The {@link VerificationMethodKeyProvider} interface method implementation using Ed25519 algorithm.
     *
     * @param message to sign
     * @return signed message
     */
    @Override
    public byte[] generateSignature(byte[] message) {
        try {
            var signer = Signature.getInstance("EdDSA", this.provider);
            signer.initSign(this.keyPair.getPrivate());
            signer.update(message);
            return signer.sign();
        } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
            // the JCE provider should be already properly initialized in the constructor
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public boolean isKeyMultibaseInSet(Set<String> multibaseEncodedKeys) {
        return multibaseEncodedKeys.contains(this.getVerificationKeyMultibase());
    }

    boolean verify(byte[] message, byte[] signature) {
        try {
            var verifier = Signature.getInstance("EdDSA", this.provider);
            verifier.initVerify(this.keyPair.getPublic());
            verifier.update(message);
            return verifier.verify(signature);
        } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
            // the JCE provider should be already properly initialized in the constructor
            throw new IllegalArgumentException(e);
        }
    }
}
