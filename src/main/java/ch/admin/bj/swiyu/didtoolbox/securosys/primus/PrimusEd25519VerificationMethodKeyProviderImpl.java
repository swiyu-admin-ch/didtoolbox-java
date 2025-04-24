package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

import ch.admin.bj.swiyu.didtoolbox.Ed25519VerificationMethodKeyProviderImpl;
import ch.admin.bj.swiyu.didtoolbox.PemUtils;
import ch.admin.bj.swiyu.didtoolbox.TdwCreator;
import ch.admin.bj.swiyu.didtoolbox.VerificationMethodKeyProvider;

import java.io.IOException;
import java.net.URL;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

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
    final private static String PEM_ENCODE_PUBLIC_KEY_METHOD = "pemEncodePublicKey";

    /**
     * The only public constructor of the class, capable of loading an already existing key material directly from a Securosys Primus HSM (cluster).
     */
    public PrimusEd25519VerificationMethodKeyProviderImpl(PrimusKeyStoreLoader primus, String alias, String password)
            throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException {

        super(primus.loadKeyPair(alias, password), primus.getKeyStore().getProvider());
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

    /**
     * A simple wrapper for PrimusEncoding#pemEncodePublicKey helper.
     */
    private static String pemEncodePublicKey(PublicKey pubKey) {
        try {
            return (String) Class.forName(ENCODER_CLASS)
                    .getMethod(PEM_ENCODE_PUBLIC_KEY_METHOD, PublicKey.class)
                    .invoke(null, pubKey);
        } catch (Exception e) {
            //} catch (ClassNotFoundException | InvocationTargetException | NoSuchMethodException | IllegalAccessException e) {
            //throw new PrimusKeyStoreInitializationException(
            throw new RuntimeException(
                    "Ensure the required lib/primusX-java[8|11].jar libraries exist on the system", e);
        }
    }

    @Override
    public String getVerificationKeyMultibase() {

        if (this.keyPair == null) {
            throw new RuntimeException("This instance features no self-generated key pair.");
        }

        // conversion (from PEM)
        try {
            return PemUtils.parsePEMPublicKeyEd25519Multibase(pemEncodePublicKey(this.keyPair.getPublic()));
        } catch (IOException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] generateSignature(byte[] message) {

        return optionallyUnderifyRS(super.generateSignature(message));
    }
}
