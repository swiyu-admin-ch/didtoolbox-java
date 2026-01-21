package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.JcsSha256Hasher;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
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
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;
import java.util.Set;

/**
 * The {@link Ed25519VerificationMethodKeyProviderImpl} class is a {@link VerificationMethodKeyProvider} implementation used to generate pairs of
 * public and private keys for the Ed25519 algorithm (or loading them from the file system). Such key pair is then used
 * for the purpose of DID (<a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> or <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>) log creation.
 * Furthermore, it also plays an essential role while <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">creating data integrity proof</a>.
 * It builds on top of {@link java.security} and introduces various useful helpers.
 * <p>
 * It is predominantly intended to be used within a:
 * <ul>
 * <li> {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext.DidLogCreatorContextBuilder#cryptographicSuite(VcDataIntegrityCryptographicSuite)} method
 * (prior to a {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext#create(URL)} call)</li>
 * <li>{@link ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext.DidLogUpdaterContextBuilder#cryptographicSuite(VcDataIntegrityCryptographicSuite)} method
 * (prior to a {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext#update(String)} call).</li>
 * </ul>
 * <p>
 * Thanks to the following constructor(s), it is also capable of loading an already existing key material from the file system:
 * <ul>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(Reader, Reader)} for loading the update (Ed25519) key from
 * <a href="https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail">PEM</a> files</li>
 * <li>{@link Ed25519VerificationMethodKeyProviderImpl#Ed25519VerificationMethodKeyProviderImpl(InputStream, String, String, String)} for loading the update (Ed25519) key from Java KeyStore (JKS) files</li>
 * </ul>
 *
 * @deprecated Use {@link ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite} instead, whenever possible. Since 1.8.0
 */
@Deprecated
@SuppressWarnings({"PMD.GodClass", "PMD.ExcessiveImports"})
public class Ed25519VerificationMethodKeyProviderImpl implements VcDataIntegrityCryptographicSuite {

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

        this.keyPair = new KeyPair(PemUtils.parsePemPublicKey(publicKeyReader), PemUtils.parsePemPrivateKey(privateKeyReader));

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

        final PrivateKey privKey = PemUtils.parsePemPrivateKey(privateKeyReader);

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
        try (var pemWriter = new PemWriter(Files.newBufferedWriter(file.toPath()))) {
            pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKeyEncoded));
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
        try (var pemWriter = new PemWriter(Files.newBufferedWriter(file.toPath()))) {
            pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKeyEncoded));
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
        return Ed25519Utils.toMultibase(this.keyPair.getPublic());
    }

    /**
     * Generate a (detached) <a href="https://www.rfc-editor.org/rfc/rfc8032">Edwards-Curve Digital Signature Algorithm (EdDSA) RFC8032</a>
     * signature for the (hashed) verification proof,
     * <a href="https://www.w3.org/TR/controller-document/#multibase-0">multibase-encoded using the base-58-btc (multibase) header and alphabet</a>.
     *
     * @param message to sign
     * @return signed message
     * @deprecated As the method {@link #addProof(String, String, String, ZonedDateTime)}
     * makes it redundant. Since 1.8.0
     */
    @Override
    @Deprecated
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

    /**
     * Add a data integrity proof to a supplied <b>unsecured data document</b> ("a map that contains no proof values"), thus producing
     * a <b>secured data document</b> ("a map that contains one or more proof values"),
     * as specified by <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">Data Integrity EdDSA Cryptosuites v1.0</a>.
     * <p>
     * See <a href="https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022">example</a>
     * <p>
     * The {@code proofValue} property of the {@code proof} MUST be a detached EdDSA signature produced according to
     * <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC8032</a>,
     * encoded using the base-58-btc header and alphabet as described in the
     * <a href="https://www.w3.org/TR/controller-document/#multibase-0">Multibase</a> section of
     * <a href="https://www.w3.org/TR/controller-document/">Controlled Identifier Document</a>.
     *
     * @param unsecuredDocument to make "secure" in terms of adding a data integrity proof to it,
     *                          as <a href="https://www.w3.org/TR/vc-data-integrity/#dfn-unsecured-data-document">specified</a>
     *                          ("unsecured data document is a map (JSON object) that contains no proof values")
     * @param challenge         self-explanatory
     * @param proofPurpose      typically "assertionMethod" or "authentication"
     * @param dateTime          of the proof creation (in <a href="https://www.rfc-editor.org/rfc/rfc3339.html">RFC3339</a> format)
     * @return String representing a "secured" document i.e. the supplied {@code unsecuredDocument} featuring a data integrity proof
     * @throws VcDataIntegrityCryptographicSuiteException if operation fails for any reason
     */
    @Override
    public String addProof(String unsecuredDocument,
                           String challenge,
                           String proofPurpose,
                           ZonedDateTime dateTime)
            throws VcDataIntegrityCryptographicSuiteException {

        JsonObject unsecuredDocumentJsonObject;
        try {
            unsecuredDocumentJsonObject = JsonParser.parseString(unsecuredDocument).getAsJsonObject();
        } catch (JsonSyntaxException | IllegalStateException ex) {
            throw new VcDataIntegrityCryptographicSuiteException(ex);
        }

        /*
        https://identity.foundation/didwebvh/v0.3/#data-integrity-proof-generation-and-first-log-entry:
        The last step in the creation of the first log entry is the generation of the data integrity proof.
        One of the keys in the updateKeys parameter MUST be used (in the form of a did:key) to generate the signature in the proof,
        with the versionId value (item 1 of the did log) used as the challenge item.
        The generated proof is added to the JSON as the fifth item, and the entire array becomes the first entry in the DID Log.
         */

        var proof = new JsonObject();

        // According to https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022:
        // 2) If unsecuredDocument.@context is present, set proof.@context to unsecuredDocument.@context.
        var ctx = unsecuredDocumentJsonObject.get("@context");
        if (ctx != null) {
            proof.add("@context", ctx);
        }

        proof.addProperty("type", DATA_INTEGRITY_PROOF);
        // According to https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
        proof.addProperty("cryptosuite", EDDSA_JCS_2022);
        proof.addProperty("created", DateTimeFormatter.ISO_INSTANT.format(dateTime.truncatedTo(ChronoUnit.SECONDS)));

        /*
        The data integrity proof verificationMethod is the did:key from the first log entry, and the challenge is the versionId from this log entry.
         */
        proof.addProperty("verificationMethod", DID_KEY + this.getVerificationKeyMultibase() + '#' + this.getVerificationKeyMultibase());
        proof.addProperty("proofPurpose", proofPurpose);
        if (challenge != null) {
            proof.addProperty("challenge", challenge);
        }

        String docHashHex;
        String proofHashHex;
        try (var hasher = JcsSha256Hasher.Companion.build()) {
            docHashHex = hasher.encodeHex(unsecuredDocumentJsonObject.toString());
            proofHashHex = hasher.encodeHex(proof.toString());
        } catch (DidSidekicksException e) {
            throw new VcDataIntegrityCryptographicSuiteException(e);
        }

        var signature = this.generateSignature(HexFormat.of().parseHex(proofHashHex + docHashHex));

        // See https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022
        //     https://www.w3.org/TR/controller-document/#multibase-0
        proof.addProperty("proofValue", 'z' + Base58.encode(signature));

        var proofs = new JsonArray();
        proofs.add(proof);
        unsecuredDocumentJsonObject.add("proof", proofs);

        return unsecuredDocumentJsonObject.toString();
    }
}
