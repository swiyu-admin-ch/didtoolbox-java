package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.model.UpdateKeysDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;

/**
 * Simple helper singleton featuring public keys (as well as cryptographic suites) required for DID log creation/update.
 * <p>
 * The keys are stored inside a ring buffer featuring unidirectional navigation via {@link #rotate()} helper.
 * <p>
 * <strong>CAUTION</strong> The sole purpose of this helper class is to assist developers while writing unit tests.
 * It is NOT intended to be used in production code.
 */
@SuppressWarnings("PMD")
public final class RandomEd25519KeyStore {

    private static RandomEd25519KeyStore instance = new RandomEd25519KeyStore(5);
    private final VcDataIntegrityCryptographicSuite[] suites;
    private final PublicKey[] keys;
    private int currentStoreIndex;

    /**
     * The only non-empty constructor of the class is private. Used to initialize the singleton instance.
     */
    private RandomEd25519KeyStore(int capacity) {
        this.currentStoreIndex = 0;
        this.suites = new VcDataIntegrityCryptographicSuite[capacity];
        this.keys = new PublicKey[capacity];

        var index = 0;
        do {
            // the Ed25519VerificationMethodKeyProviderImpl() would also work, but is deprecated
            var suite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
            suites[index] = suite;
            Path publicPEM = null;
            try {
                publicPEM = Files.createTempFile("mypublic", "");
                suite.writePublicKeyPemFile(publicPEM);
                // instead of: keys[index] = PemUtils.parsePemPublicKey(Files.newBufferedReader(publicPEM));
                final PEMParser parser = new PEMParser(Files.newBufferedReader(publicPEM));
                var pemObj = parser.readObject();
                if (pemObj instanceof SubjectPublicKeyInfo) {
                    keys[index] = new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) pemObj);
                } else {
                    throw new IllegalArgumentException("The supplied reader features no PEM-encoded public key");
                }

            } catch (VcDataIntegrityCryptographicSuiteException | IOException e) {
                throw new RuntimeException(e);
            } finally {
                if (publicPEM != null) publicPEM.toFile().deleteOnExit();
            }

        } while (++index < suites.length);
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
        if (instance.currentStoreIndex == instance.suites.length - 1) instance.currentStoreIndex = -1;

        instance.currentStoreIndex++;

        return instance;
    }

    /**
     * @return the actual capacity of the key store - may be (re)set via {@link #init(int)}.
     */
    public static int getCapacity() {
        return instance.suites.length;
    }

    /**
     * A handy helper to be used for the purpose od supplying a cryptographic suite required to create/update a DID log entry.
     */
    public static VcDataIntegrityCryptographicSuite cryptographicSuite() {
        return instance.suites[instance.currentStoreIndex];
    }

    /**
     * The getter of a public key (from the store) w.r.t. current ring buffer (read) pointer.
     * <p>
     * It that may be used for the purpose od supplying values for any of
     * {@code updateKeys}/{@code nextKeyHashes} DID method parameters
     * via static factory methods {@link UpdateKeysDidMethodParameter#of(PublicKey)}
     * and/or {@link NextKeyHashesDidMethodParameter#of(PublicKey)}
     */
    public PublicKey getPublicKey() {
        return instance.keys[instance.currentStoreIndex];
    }
}