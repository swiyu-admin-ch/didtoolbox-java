package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

import ch.admin.bj.swiyu.didtoolbox.Ed25519VerificationMethodKeyProviderImpl;
import ch.admin.bj.swiyu.didtoolbox.TdwCreator;
import ch.admin.bj.swiyu.didtoolbox.VerificationMethodKeyProvider;

import java.net.URL;
import java.security.*;
import java.util.Set;

/**
 * The {@link PrimusEd25519VerificationMethodKeyProviderImpl} class is a {@link VerificationMethodKeyProvider} implementation
 * relying completely on Securosys Primus HSM cluster as source of pairs of public and private keys for the Ed25519 algorithm.
 * Such key pair is used then for the purpose of <a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> log creation.
 * Furthermore, it also plays an essential role while <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">creating data integrity proof</a>.
 * It builds extensively on top of {@link Ed25519VerificationMethodKeyProviderImpl} and introduces various useful Primus HSM-related helpers.
 * <p>
 * It is predominantly intended to be used within the {@link TdwCreator.TdwCreatorBuilder#verificationMethodKeyProvider} method
 * prior to a {@link TdwCreator#create(URL)} call.
 * <p>
 * Thanks to the following constructors, it is also capable of loading an already existing key material directly from a Securosys Primus HSM (cluster):
 * <ul>
 * <li>{@link PrimusEd25519VerificationMethodKeyProviderImpl#PrimusEd25519VerificationMethodKeyProviderImpl(PrimusKeyStoreLoader, String, String)}</li>
 * </ul>
 */
public class PrimusEd25519VerificationMethodKeyProviderImpl extends Ed25519VerificationMethodKeyProviderImpl {

    final private static String ENCODER_CLASS = "com.securosys.primus.jce.PrimusEncoding";
    final private static String UNDERIFY_METHOD = "optionallyUnderifyRS";

    private PrimusEd25519VerificationMethodKeyProviderImpl() {
        super();
    }

    private PrimusEd25519VerificationMethodKeyProviderImpl(KeyPair keyPair, Provider provider) {
        super(keyPair, provider);
    }

    /**
     * The only public constructor of the class, capable of loading an already existing key material directly from a Securosys Primus HSM (cluster).
     */
    public PrimusEd25519VerificationMethodKeyProviderImpl(PrimusKeyStoreLoader primus, String alias, String password) throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException {

        var keyStore = primus.getKeyStore();

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

        // CAUTION In case of Securosys JCE provider for Securosys Primus HSM ("SecurosysPrimusXSeries"), key translation is required
        final KeyFactory keyFactory = KeyFactory.getInstance("EC", keyStore.getProvider());
        // Translate a key object (whose provider may be unknown or potentially untrusted) into a corresponding key object of this key factory
        publicKey = (PublicKey) keyFactory.translateKey(cert.getPublicKey()); // "exported key"

        new PrimusEd25519VerificationMethodKeyProviderImpl(new KeyPair(publicKey, key), keyStore.getProvider());
    }

    /**
     * A simple wrapper for PrimusEncoding#optionallyUnderifyRS helper.
     */
    private static byte[] optionallyUnderifyRS(byte[] signed) {
        try {
            return (byte[]) Class.forName(ENCODER_CLASS)
                    .getMethod(UNDERIFY_METHOD, byte[].class)
                    .invoke(null, signed);
        } catch (Exception e) {
            //} catch (ClassNotFoundException | InvocationTargetException | NoSuchMethodException | IllegalAccessException e) {
            //throw new PrimusKeyStoreInitializationException(
            throw new RuntimeException(
                    "Ensure the required lib/primusX-java[8|11].jar libraries exist on the system", e);
        }
    }

    @Override
    public byte[] generateSignature(byte[] message) {

        return optionallyUnderifyRS(super.generateSignature(message));
    }

    @Override
    public boolean isKeyMultibaseInSet(Set<String> multibaseEncodedKeys) {
        return true;
    }
}
