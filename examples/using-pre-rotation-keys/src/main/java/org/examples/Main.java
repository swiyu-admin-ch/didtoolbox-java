package org.examples;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;

public class Main {

    public static void main(String... args) {

        // The helper key store having default capacity is 5 (keys)
        RandomEd25519KeyStore.init(10);

        try {
            System.out.println(build());
        } catch (URISyntaxException | IOException | DidLogCreatorStrategyException | DidLogUpdaterStrategyException |
                 InvalidKeySpecException | NextKeyHashesDidMethodParameterException | VerificationMethodException err) {
            System.err.println(err.getMessage());
            System.exit(1);
        }

        System.exit(0);
    }

    static String build() throws URISyntaxException, IOException, DidLogCreatorStrategyException,
            DidLogUpdaterStrategyException, InvalidKeySpecException, NextKeyHashesDidMethodParameterException, VerificationMethodException {

        // initial DID log entry
        var didLog = new StringBuilder(
                // initial (by default, did:webvh:1.0) DID log entry (featuring a pre-rotation key)
                DidLogCreatorContext.builder()
                        .cryptographicSuite(RandomEd25519KeyStore.cryptographicSuite())
                        // IMPORTANT Calling this method activates key pre-rotation
                        .nextKeyHashesDidMethodParameter(Set.of(
                                // get a whole another pre-rotation key to be used when building the next DID log entry.
                                // Bear in mind, after the key store "rotation", all its (static) helpers "point" to the next/another key in the store
                                NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                                // REMINDER Indeed, you may keep adding more keys this way - beware that some of them
                                //          MUST entirely match the "updateKeys" values in the DID log next entry
                                //,NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                                //,NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                        ))
                        .assertionMethods(Set.of(VerificationMethod.of("my-assert-key-01", Path.of("../../src/test/data/assert-key-01.pub"))))
                        //.authentications(Set.of(VerificationMethod.of("my-auth-key-01", Path.of("../../src/test/data/auth-key-01.pub"))))
                        .build()
                        .create(URL.of(new URI("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085"), null))
        ).append(System.lineSeparator());

        // Update the DID log by adding as many entries as there are keys in the store.
        // Keep "rotating" (pre-rotation) keys while updating
        var i = 0;
        while (i++ < RandomEd25519KeyStore.getCapacity()) {

            didLog.append(
                    // next DID log entry
                    DidLogUpdaterContext.builder()
                            // switch to the key defined by the "nextKeyHashes" from the previous entry (the key store is already "rotated" earlier)
                            .cryptographicSuite(RandomEd25519KeyStore.cryptographicSuite())
                            // Prepare ("rotate" to) another pre-rotation key to be used when building the next DID log entry
                            .nextKeyHashesDidMethodParameter(Set.of(
                                    // Bear in mind, after the key store "rotation", all its (static) helpers "point" to the next/another key in the store
                                    NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                                    // REMINDER Indeed, you may keep adding more keys this way - beware that some of them
                                    //          MUST entirely match the "updateKeys" values in the DID log next entry
                                    //,NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                                    //,NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                            ))
                            .assertionMethods(Set.of(VerificationMethod.of("my-assert-key-0" + i, Path.of("../../src/test/data/assert-key-01.pub"))))
                            .authentications(Set.of(VerificationMethod.of("my-auth-key-0" + i, Path.of("../../src/test/data/auth-key-01.pub"))))
                            .build()
                            .update(didLog.toString())
            ).append(System.lineSeparator());
        }

        return didLog.toString();
    }

    /**
     * Simple helper singleton featuring public keys (as well as cryptographic suites) required for DID log creation/update.
     * <p>
     * The keys are stored inside a ring buffer featuring unidirectional navigation via {@link #rotate()} helper
     * <p>
     * <strong>CAUTION</strong> The sole purpose of this helper class is to assist developers while writing unit tests.
     * It is NOT intended to be used in production code.
     */
    static class RandomEd25519KeyStore {

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
        static RandomEd25519KeyStore rotate() {
            if (instance.currentStoreIndex == instance.suites.length - 1) instance.currentStoreIndex = -1;

            instance.currentStoreIndex++;

            return instance;
        }

        /**
         * @return the actual capacity of the key store - may be (re)set via {@link #init(int)}.
         */
        static int getCapacity() {
            return instance.suites.length;
        }

        /**
         * A handy helper to be used for the purpose od supplying a cryptographic suite required to create/update a DID log entry.
         */
        static VcDataIntegrityCryptographicSuite cryptographicSuite() {
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
        PublicKey getPublicKey() {
            return instance.keys[instance.currentStoreIndex];
        }
    }
}