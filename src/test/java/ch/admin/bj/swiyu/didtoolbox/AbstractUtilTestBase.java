package ch.admin.bj.swiyu.didtoolbox;

import java.io.*;
import java.net.URI;
import java.net.URL;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

/**
 * The base class for all test class in this package relying on test data of any kind.
 * Some handy helpers included, too.
 */
abstract class AbstractUtilTestBase {
    final public static String DATA_PATH_PREFIX = "src/test/data/";

    final public static String ISO_DATE_TIME = "2012-12-12T12:12:12Z";
    // final private static VerificationMethodKeyProvider VERIFICATION_METHOD_KEY_PROVIDER;
    final static VerificationMethodKeyProvider VERIFICATION_METHOD_KEY_PROVIDER_JKS;

    /**
     * Sharing the very same keys with {@code EXAMPLE_POP_JWS_SIGNER}
     */
    final static VerificationMethodKeyProvider EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER;
    /**
     * Sharing the very same keys with {@code EXAMPLE_POP_JWS_SIGNER_ANOTHER}
     */
    final static VerificationMethodKeyProvider EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER;

    final static Map<String, String> ASSERTION_METHOD_KEYS;
    final static Map<String, String> AUTHENTICATION_METHOD_KEYS;

    final static String PRIVATE_KEY_MULTIBASE = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";
    final static String PUBLIC_KEY_MULTIBASE = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    /**
     * Sharing the very same keys with {@code EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER}
     */
    final static ProofOfPossessionJWSSigner EXAMPLE_POP_JWS_SIGNER;
    /**
     * Sharing the very same keys with {@code EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER}
     */
    final static ProofOfPossessionJWSSigner EXAMPLE_POP_JWS_SIGNER_ANOTHER;

    // PRIVATE_KEY & PUBLIC_KEY are a different keypair than their MULTIBASE counterparts.
    final static byte[] PRIVATE_KEY_ANOTHER;
    final static byte[] PUBLIC_KEY_ANOTHER;

    static {
        // From https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-0
        EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER = new UnsafeEd25519VerificationMethodKeyProviderImpl(
                PRIVATE_KEY_MULTIBASE, PUBLIC_KEY_MULTIBASE);
        EXAMPLE_POP_JWS_SIGNER = new UnsafeEd25519ProofOfPossessionJWSSignerImpl(
                PRIVATE_KEY_MULTIBASE, PUBLIC_KEY_MULTIBASE);

        try {
            // Total 3 (PrivateKeyEntry) entries available in the JKS: myalias/myalias2/myalias3
            VERIFICATION_METHOD_KEY_PROVIDER_JKS = new Ed25519VerificationMethodKeyProviderImpl(
                    new FileInputStream(DATA_PATH_PREFIX + "mykeystore.jks"), "changeit", "myalias", "changeit");

            ASSERTION_METHOD_KEYS = Map.of("my-assert-key-01", JwkUtils.loadECPublicJWKasJSON(new File(DATA_PATH_PREFIX + "assert-key-01.pub"), "my-assert-key-01"));
            AUTHENTICATION_METHOD_KEYS = Map.of("my-auth-key-01", JwkUtils.loadECPublicJWKasJSON(new File(DATA_PATH_PREFIX + "auth-key-01.pub"), "my-auth-key-01"));
        } catch (Exception intolerable) {
            throw new RuntimeException(intolerable);
        }

        try {
            var publicKeyFile = new File(DATA_PATH_PREFIX + "public01.pem");
            var privateKeyFile = new File(DATA_PATH_PREFIX + "private01.pem");
            var signer = new Ed25519VerificationMethodKeyProviderImpl(new FileReader(privateKeyFile), new FileReader(publicKeyFile)); // supplied external key pair
            EXAMPLE_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER = signer;
            EXAMPLE_POP_JWS_SIGNER_ANOTHER = new Ed25519ProofOfPossessionJWSSignerImpl(new FileReader(privateKeyFile), new FileReader(publicKeyFile)); // supplied external key pair
            PRIVATE_KEY_ANOTHER = decodeEncodedKey(signer.keyPair.getPrivate().getEncoded());
            PUBLIC_KEY_ANOTHER = decodeEncodedKey(signer.keyPair.getPublic().getEncoded());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Also features an updateKey matching {@link #VERIFICATION_METHOD_KEY_PROVIDER_JKS}.
     *
     * @param verificationMethodKeyProvider
     * @return
     */
    static String buildInitialDidLogEntry(VerificationMethodKeyProvider verificationMethodKeyProvider) {
        try {
            return TdwCreator.builder()
                    .verificationMethodKeyProvider(verificationMethodKeyProvider)
                    .assertionMethodKeys(ASSERTION_METHOD_KEYS)
                    .authenticationKeys(AUTHENTICATION_METHOD_KEYS)
                    .updateKeys(Set.of(new File(DATA_PATH_PREFIX + "public.pem"))) // to be able to use VERIFICATION_METHOD_KEY_PROVIDER while updating
                    .build()
                    .create(URL.of(new URI("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085"), null), ZonedDateTime.parse(ISO_DATE_TIME));
        } catch (Exception simplyIntolerable) {
            throw new RuntimeException(simplyIntolerable);
        }
    }

    static byte[] decodeEncodedKey(byte[] encodedKey) {
        final int KEY_LENGTH = 32;
        return Arrays.copyOfRange(encodedKey, encodedKey.length - KEY_LENGTH, encodedKey.length);
    }
}
