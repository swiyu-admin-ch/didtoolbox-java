package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

import ch.admin.bj.swiyu.didtoolbox.Ed25519VerificationMethodKeyProviderImpl;
import ch.admin.bj.swiyu.didtoolbox.VerificationMethodKeyProvider;

import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;

/**
 * The {@link PrimusEd25519VerificationMethodKeyProviderImpl} class is a {@link VerificationMethodKeyProvider} implementation
 * built on top of {@link Ed25519VerificationMethodKeyProviderImpl}
 * relying completely on Securosys Primus HSM cluster as source of key pairs for the Ed25519 algorithm.
 * Such key pair is then used for the purpose of DID (<a href="https://identity.foundation/didwebvh/v0.3">did:tdw</a> or <a href="https://identity.foundation/didwebvh/v1.0">did:webvh</a>) log creation.
 * Furthermore, it also plays an essential role while <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">creating data integrity proof</a>.
 * <p>
 * It is predominantly intended to be used within a:
 * <ul>
 * <li> {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext.DidLogCreatorContextBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} method
 * (prior to a {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext#create(URL)} call)</li>
 * <li>{@link ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext.DidLogUpdaterContextBuilder#verificationMethodKeyProvider(VerificationMethodKeyProvider)} method
 * (prior to a {@link ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext#update(String)} call).</li>
 * </ul>
 * <p>
 * Thanks to the following constructor(s), it is capable of loading an already existing key material directly from a Securosys Primus HSM (cluster):
 * <ul>
 * <li>{@link PrimusEd25519VerificationMethodKeyProviderImpl#PrimusEd25519VerificationMethodKeyProviderImpl(PrimusKeyStoreLoader, String, String)}</li>
 * </ul>
 */
public class PrimusEd25519VerificationMethodKeyProviderImpl extends Ed25519VerificationMethodKeyProviderImpl {

    final protected static String ENCODER_CLASS = "com.securosys.primus.jce.PrimusEncoding";
    final protected static String UNDERIFY_METHOD = "optionallyUnderifyRS";

    /**
     * The only public constructor of the class, capable of loading an already existing key material directly from a Securosys Primus HSM (cluster).
     */
    @SuppressWarnings({"PMD.LawOfDemeter"})
    public PrimusEd25519VerificationMethodKeyProviderImpl(PrimusKeyStoreLoader primus, String alias, String password)
            throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException {

        super(primus.loadKeyPair(alias, password), primus.getKeyStore().getProvider());
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

    @Override
    public byte[] generateSignature(byte[] message) {

        return optionallyUnderifyRS(super.generateSignature(message));
    }
}
