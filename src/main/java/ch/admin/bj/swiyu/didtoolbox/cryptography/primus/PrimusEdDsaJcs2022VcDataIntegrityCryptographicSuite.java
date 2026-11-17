package ch.admin.bj.swiyu.didtoolbox.cryptography.primus;

import ch.admin.bj.swiyu.didtoolbox.cryptography.Ed25519Utils;
import ch.admin.bj.swiyu.didtoolbox.cryptography.PemUtils;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.did.VerificationMethodKeyProvider;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogDeactivatorContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogUpdaterContext;
import lombok.Getter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

/**
 * The {@link PrimusEdDsaJcs2022VcDataIntegrityCryptographicSuite} class is a {@link VerificationMethodKeyProvider} implementation
 * supports the generation of new keys, instantiation with a java key store, private and public key readers and
 * relying completely on Securosys Primus HSM cluster as source of key pairs for the Ed25519 algorithm.
 * Such key pair is then used for the purpose of DID (<a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> or <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>) log creation.
 * Furthermore, it also plays an essential role while <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">creating data integrity proof</a>.
 * <p>
 * It is predominantly intended to be used within a:
 * <ul>
 * <li> {@link DidLogCreatorContext} method
 * (prior to a {@link DidLogCreatorContext#create(URL)} call)</li>
 * <li>{@link DidLogUpdaterContext} method
 * (prior to a {@link DidLogUpdaterContext#update(String)} call).</li>
 * <li>{@link DidLogDeactivatorContext} method
 * (prior to a {@link DidLogDeactivatorContext#deactivate(String)} call).</li>
 * </ul>
 * <p>
 * Thanks to the following constructor(s), it is capable of loading an already existing key material directly from a Securosys Primus HSM (cluster):
 * <ul>
 * <li>{@link PrimusEdDsaJcs2022VcDataIntegrityCryptographicSuite#PrimusEdDsaJcs2022VcDataIntegrityCryptographicSuite(PrimusKeyStoreLoader, String, char[])}</li>
 * </ul>
 */
public class PrimusEdDsaJcs2022VcDataIntegrityCryptographicSuite implements VcDataIntegrityCryptographicSuite {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    final protected static String ENCODER_CLASS = "com.securosys.primus.jce.PrimusEncoding";
    final protected static String UNDERIFY_METHOD = "optionallyUnderifyRS";
    private final static String DEFAULT_JCE_PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;

    @Getter
    private final KeyPair keyPair;
    private Provider provider = Security.getProvider(DEFAULT_JCE_PROVIDER_NAME);

    public PrimusEdDsaJcs2022VcDataIntegrityCryptographicSuite(KeyPair ed25519KeyPair, Provider provider) {
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

        sanityCheck();
    }

    /**
     * The only public constructor of the class, capable of loading an already existing key material directly from a Securosys Primus HSM (cluster).
     */
    public PrimusEdDsaJcs2022VcDataIntegrityCryptographicSuite(PrimusKeyStoreLoader primus, String alias, char[] password)
            throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException {
        this(primus.loadKeyPair(alias, password), primus.getKeyStore().getProvider());
    }

    public PrimusEdDsaJcs2022VcDataIntegrityCryptographicSuite(KeyPair keyPair, PrimusKeyStoreLoader primus) {
        this(keyPair, primus.getKeyStore().getProvider());
    }

    /**
     * A simple wrapper for PrimusEncoding#optionallyUnderifyRS helper.
     */
    protected static byte[] optionallyUnderifyRS(byte[] signed) {
        try {
            return (byte[]) Class.forName(ENCODER_CLASS)
                    .getMethod(UNDERIFY_METHOD, byte[].class)
                    .invoke(null, signed);
        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException |
                 InvocationTargetException e) {
            //throw new PrimusKeyStoreInitializationException(
            throw new IllegalArgumentException(
                    "Ensure the required lib/primusX-java[8|11].jar libraries exist on the system", e);
        }
    }

    /**
     * Generate a (detached) <a href="https://www.rfc-editor.org/rfc/rfc8032">Edwards-Curve Digital Signature Algorithm (EdDSA) RFC8032</a>
     * signature for the (hashed) verification proof,
     * <a href="https://www.w3.org/TR/controller-document/#multibase-0">multibase-encoded using the base-58-btc (multibase) header and alphabet</a>.
     *
     * @param message to sign
     * @return signed message
     * makes it redundant. Since 1.8.0
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

    public boolean verify(byte[] message, byte[] signature) {
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
     * The private/public keys (supplied within {@link #keyPair}) should match. Otherwise, {@link IllegalArgumentException} is thrown.
     */
    private void sanityCheck() {

        // alphanumerical chars falls within  ['0':'z'] range with...
        var generatedString = new Random().ints(48, 122 + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97)) // ...with two gaps inbetween
                .limit(1024) // the higher, the better
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        if (!this.verify(generatedString.getBytes(StandardCharsets.UTF_8), this.generateSignature(generatedString.getBytes(StandardCharsets.UTF_8)))) {
            throw new IllegalArgumentException("supplied keys do not match");
        }
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
    private static PrimusEdDsaJcs2022VcDataIntegrityCryptographicSuite createFromKeyStore(KeyStore keyStore, String alias, String password)
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

        return new PrimusEdDsaJcs2022VcDataIntegrityCryptographicSuite(new KeyPair(publicKey, key), keyStore.getProvider());
    }

}
