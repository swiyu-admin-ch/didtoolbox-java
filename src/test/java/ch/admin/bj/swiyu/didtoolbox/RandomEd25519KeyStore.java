package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.model.UpdateKeysDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.eid.did_sidekicks.Ed25519SigningKey;

/**
 * Simple helper singleton featuring keys required for DID log creation/update.
 * </p>
 * <strong>CAUTION</strong> The sole purpose of the helper class is to help making code examples simple.
 * It is NOT intended to be used in production code.
 */
public class RandomEd25519KeyStore {

    private static RandomEd25519KeyStore instance = new RandomEd25519KeyStore(5);
    private final Generated[] keyStore;
    private int currentKeyStoreIndex;

    /**
     * The only non-empty constructor of the class is private. Used to initialize the singleton instance.
     */
    private RandomEd25519KeyStore(int capacity) {
        this.currentKeyStoreIndex = 0;
        this.keyStore = new Generated[capacity];
        var index = 0;
        while (index < keyStore.length) try (var key = Ed25519SigningKey.Companion.generate()) {
            var gen = new Generated();
            gen.verifyingKeyMultibase = key.getVerifyingKey().toMultibase();
            try {
                gen.cryptographicSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(key.toMultibase());
            } catch (VcDataIntegrityCryptographicSuiteException e) {
                throw new RuntimeException(e);
            }
            keyStore[index++] = gen;
        }
    }

    static void init(int capacity) {
        instance = new RandomEd25519KeyStore(capacity);
    }

    /**
     * "Rotate" to next available key in the store while behaving/acting as ring buffer,
     * hence as soon the capacity limit of the store is reached, it continues rotating from the start.
     * <p>
     * In other words, after key store "rotation", all the (static) helpers simply "point" to the next/another key in the store.
     */
    public static RandomEd25519KeyStore rotate() {
        if (instance.currentKeyStoreIndex == instance.keyStore.length - 1) instance.currentKeyStoreIndex = -1;

        instance.currentKeyStoreIndex++;

        return instance;
    }

    /**
     * @return the actual capacity of the key store - may be (re)set via {@link #init(int)}.
     */
    public static int getCapacity() {
        return instance.keyStore.length;
    }

    /**
     * A handy helper to be used for the purpose od supplying values for the {@code updateKeys} DID method parameter.
     */
    public static UpdateKeysDidMethodParameter asUpdateKeysDidMethodParameter() {
        return UpdateKeysDidMethodParameter.of(instance.keyStore[instance.currentKeyStoreIndex].verifyingKeyMultibase);
    }

    /**
     * A handy helper to be used for the purpose od supplying values for the {@code nextKeyHashes} DID method parameter.
     */
    public static NextKeyHashesDidMethodParameter asNextKeyHashesDidMethodParameter() {
        return NextKeyHashesDidMethodParameter.of(instance.keyStore[instance.currentKeyStoreIndex].verifyingKeyMultibase);
    }

    /**
     * A handy helper to be used for the purpose od supplying a cryptographic suite required to create/update a DID log entry.
     */
    public static VcDataIntegrityCryptographicSuite asCryptographicSuite() {
        return instance.keyStore[instance.currentKeyStoreIndex].cryptographicSuite;
    }

    /**
     * Holder of all the key-related objects.
     */
    final private static class Generated {
        String verifyingKeyMultibase;
        VcDataIntegrityCryptographicSuite cryptographicSuite;
    }
}