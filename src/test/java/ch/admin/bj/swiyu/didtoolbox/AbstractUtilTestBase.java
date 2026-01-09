package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryCreator;
import ch.admin.eid.did_sidekicks.DidSidekicksException;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * The base class for all test class in this package relying on test data of any kind.
 * Some handy helpers included, too.
 */
@SuppressWarnings("PMD")
public abstract class AbstractUtilTestBase {
    final protected static String TEST_DATA_PATH_PREFIX = "src/test/data/";

    final protected static String ISO_DATE_TIME = "2012-12-12T12:12:12Z";

    final protected static String TEST_DID_URL = """
            https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085""";

    /**
     * Sharing the very same keys with {@link #TEST_POP_JWS_SIGNER_JKS}
     */
    final protected static VerificationMethodKeyProvider TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS;

    /**
     * Sharing the very same keys ({@link #TEST_PRIVATE_KEY_MULTIBASE}, {@link #TEST_PUBLIC_KEY_MULTIBASE}) with {@link #TEST_POP_JWS_SIGNER}
     */
    final protected static VerificationMethodKeyProvider TEST_VERIFICATION_METHOD_KEY_PROVIDER;

    /**
     * Sharing the very same keys with {@link #TEST_POP_JWS_SIGNER_ANOTHER}
     */
    final protected static VerificationMethodKeyProvider TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER;

    final protected static Map<String, String> TEST_ASSERTION_METHOD_KEYS;
    final protected static Map<String, String> TEST_AUTHENTICATION_METHOD_KEYS;

    /**
     * The Ed25519 private key matching {@link #TEST_PUBLIC_KEY_MULTIBASE} and delivered by {@link #TEST_VERIFICATION_METHOD_KEY_PROVIDER}
     *
     * @see <a href="https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-0">example</a>
     */
    final protected static String TEST_PRIVATE_KEY_MULTIBASE = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

    /**
     * The Ed25519 public key matching {@link #TEST_PRIVATE_KEY_MULTIBASE} and delivered by {@link #TEST_VERIFICATION_METHOD_KEY_PROVIDER}
     *
     * @see <a href="https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-0">example</a>
     */
    final protected static String TEST_PUBLIC_KEY_MULTIBASE = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";

    /**
     * Sharing the very same keys with {@link #TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS}
     */
    final protected static ProofOfPossessionJWSSigner TEST_POP_JWS_SIGNER_JKS;

    /**
     * Sharing the very same keys ({@link #TEST_PRIVATE_KEY_MULTIBASE}, {@link #TEST_PUBLIC_KEY_MULTIBASE}) with {@link #TEST_VERIFICATION_METHOD_KEY_PROVIDER}
     */
    final protected static ProofOfPossessionJWSSigner TEST_POP_JWS_SIGNER;

    /**
     * Sharing the very same keys with {@link #TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER}
     */
    final protected static ProofOfPossessionJWSSigner TEST_POP_JWS_SIGNER_ANOTHER;

    /**
     * The private key delivered by {@link #TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER}
     */
    final protected static byte[] TEST_PRIVATE_KEY_ANOTHER;

    /**
     * The public key delivered by {@link #TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER}
     */
    final protected static byte[] TEST_PUBLIC_KEY_ANOTHER;

    /**
     * Collection of signing/verifying Ed25519 keys in various (appropriate) format intended for testing purposes only
     * <p>
     * All the lines in this keypair matrix were generated using the {@code openssl} command by running the following script:
     * <pre>
     * openssl genpkey -algorithm ed25519 -out private.pem
     * openssl pkey -inform pem -in private.pem -outform der -out private.der
     * cat private.pem | openssl pkey -pubout -outform der -out public.der
     * cat private.pem | openssl pkey -pubout -out public.pem
     * secret_key_multibase=z$(echo 8026$(xxd -plain -cols 32 -s -32 private.der) | xxd -r -p | bs58)
     * public_key_multibase=z$(echo ed01$(xxd -plain -cols 32 -s -32 public.der)  | xxd -r -p | bs58)
     * echo "{\"${secret_key_multibase}\", \"${public_key_multibase}\", \"\"\"\n$(cat private.pem)\n\"\"\", \"\"\"\n$(cat public.pem)\n\"\"\"}"
     * </pre>
     */
    final protected static String[][] TEST_KEYS = new String[][]{
            {"z3u2iCfD6b5dW4vV9b8uF1xb2t2SZGETfBsyjhfTF4in4CLc", "z6Mkqc1baWFKrggkLZKUENm5miHajNsZLAAWk14rhx46Xkik", """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPxLZijS8GbSE105Xjiofms8nRKTxOWBJQQY/M8esjGl
-----END PRIVATE KEY-----
""", """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApa5yTiKfpVZbJYY6K0KwtdnAG9R8vWq8X/9gE1nylCE=
-----END PUBLIC KEY-----
"""},
            {"z3u2UUEtR41WAyKAcaGmLzgfjANKt6dcwT5YRmkUUyFdZo1f", "z6MkmSMnpy1m61MmrPyK9XbmqnvZGgzgd9mSU4cqHpFBqU14", """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDBFku6dTtnlOouoxDJHztCYn3phCwgxbKphopaz+pke
-----END PRIVATE KEY-----
""", """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAZ8a5Xaab/uXt8dwuVsyY7dhyLA0phIPnboYMfZdDu28=
-----END PUBLIC KEY-----
"""},
            {"z3u2eJ6TNxhz7uWMVCo2EXmu2B9CmT2BMjMYbQoNCgHqDR54", "z6MktBBGPxxRehpwAidG9fpLyPg9juRnc2w8syn5R5nRZyaS", """
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMJBGfbOGJR5Un3X2gZ1q5xQp/vWa50iL3OZZnnyqAdr
-----END PRIVATE KEY-----
""", """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAy+TrjsokNmoMEyOPm/6e9Vw+CPP3KAAKd9D9ZKsE/hM=
-----END PUBLIC KEY-----
"""}
    };

    /**
     * Private PEM files extracted from {@link #TEST_KEYS} intended for testing purposes only
     */
    final protected static File[] TEST_SIGNING_KEY_FILES = new File[TEST_KEYS.length];

    /**
     * Public PEM files extracted from {@link #TEST_KEYS} intended for testing purposes only
     */
    final protected static File[] TEST_KEY_FILES = new File[TEST_KEYS.length];

    /**
     * VerificationMethodKeyProvider objects extracted from {@link #TEST_KEYS}
     */
    final protected static VerificationMethodKeyProvider[] TEST_SIGNERS = new VerificationMethodKeyProvider[TEST_KEYS.length];

    static {
        // Populate TEST_* arrays
        int i = 0;
        for (var key : TEST_KEYS) {
            File privateKeyPemFile, publicKeyPemFile;
            try {
                privateKeyPemFile = File.createTempFile("myprivatekey", "");
                publicKeyPemFile = File.createTempFile("mypublickey", "");
                TEST_SIGNERS[i] = new DalekEd25519VerificationMethodKeyProviderImpl(key[0]);
                Files.writeString(privateKeyPemFile.toPath(), key[2]);
                Files.writeString(publicKeyPemFile.toPath(), key[3]);
                TEST_SIGNING_KEY_FILES[i] = privateKeyPemFile;
                TEST_KEY_FILES[i++] = publicKeyPemFile;
            } catch (IOException | DidSidekicksException intolerable) {
                //} catch (IOException intolerable) {
                throw new IllegalArgumentException(intolerable);
            }
            privateKeyPemFile.deleteOnExit();
            publicKeyPemFile.deleteOnExit();
        }

        try {
            // Using (example) keys from https://www.w3.org/TR/vc-di-eddsa/#example-private-and-public-keys-for-signature-0
            TEST_POP_JWS_SIGNER = new DalekEd25519ProofOfPossessionJWSSignerImpl(TEST_PRIVATE_KEY_MULTIBASE);
            TEST_VERIFICATION_METHOD_KEY_PROVIDER = TEST_POP_JWS_SIGNER;

            // Total 3 (PrivateKeyEntry) entries available in the JKS: myalias/myalias2/myalias3
            TEST_POP_JWS_SIGNER_JKS = new Ed25519ProofOfPossessionJWSSignerImpl(
                    Files.newInputStream(Path.of(TEST_DATA_PATH_PREFIX + "mykeystore.jks")), "changeit", "myalias", "changeit");
            TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS = TEST_POP_JWS_SIGNER_JKS;

            TEST_ASSERTION_METHOD_KEYS = Map.of("my-assert-key-01",
                    JwkUtils.loadECPublicJWKasJSON(new File(TEST_DATA_PATH_PREFIX + "assert-key-01.pub"), "my-assert-key-01"));
            TEST_AUTHENTICATION_METHOD_KEYS = Map.of("my-auth-key-01",
                    JwkUtils.loadECPublicJWKasJSON(new File(TEST_DATA_PATH_PREFIX + "auth-key-01.pub"), "my-auth-key-01"));
        } catch (Exception intolerable) {
            throw new IllegalArgumentException(intolerable);
        }

        try {
            var signer = new Ed25519ProofOfPossessionJWSSignerImpl(
                    Files.newBufferedReader(Path.of(TEST_DATA_PATH_PREFIX + "private01.pem")),
                    Files.newBufferedReader(Path.of(TEST_DATA_PATH_PREFIX + "public01.pem"))); // supplied external key pair
            TEST_POP_JWS_SIGNER_ANOTHER = signer;
            TEST_VERIFICATION_METHOD_KEY_PROVIDER_ANOTHER = TEST_POP_JWS_SIGNER_ANOTHER;
            TEST_PRIVATE_KEY_ANOTHER = decodeEncodedKey(signer.keyPair.getPrivate().getEncoded());
            TEST_PUBLIC_KEY_ANOTHER = decodeEncodedKey(signer.keyPair.getPublic().getEncoded());
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    protected static Collection<URL> identifierRegistryUrl() throws URISyntaxException, MalformedURLException {
        return Arrays.asList(
                URL.of(new URI("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085"), null),
                URL.of(new URI("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085/did.jsonl"), null)
        );
    }

    /**
     * Self-explanatory.
     */
    protected static File writeStringToTempFile(String str) {
        File tempFile;
        try {
            tempFile = File.createTempFile("mytempfile", "");
            Files.writeString(tempFile.toPath(), str);
        } catch (IOException intolerable) {
            throw new IllegalArgumentException(intolerable);
        }
        tempFile.deleteOnExit();
        return tempFile;
    }

    /**
     * The helper delivers an initial {@code did:tdw} DID log entry featuring the {@code updateKey} provided by {@link #TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS}.
     *
     * @param signer to be used for signing the new {@code did:tdw} DID log
     * @return a valid DID log
     * @see #buildInitialWebVerifiableHistoryDidLogEntry(VerificationMethodKeyProvider)
     */
    protected static String buildInitialTdwDidLogEntry(VerificationMethodKeyProvider signer) {

        AtomicReference<String> didLog = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            didLog.set(TdwCreator.builder()
                    .verificationMethodKeyProvider(signer)
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .updateKeys(Set.of(new File(TEST_DATA_PATH_PREFIX + "public.pem"))) // to be able to use VERIFICATION_METHOD_KEY_PROVIDER while updating
                    .build()
                    .createDidLog(URL.of(new URI(TEST_DID_URL), null), ZonedDateTime.parse(ISO_DATE_TIME)));
        });

        return didLog.get();
    }

    /**
     * The helper delivers an initial {@code did:webvh} DID log entry featuring the {@code updateKey} provided by {@link #TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS}.
     *
     * @param signer to be used for signing the new {@code did:webvh} DID log
     * @return a valid {@code did:webvh} DID log entry
     * @see #buildInitialTdwDidLogEntry(VerificationMethodKeyProvider)
     */
    protected static String buildInitialWebVerifiableHistoryDidLogEntry(VerificationMethodKeyProvider signer) {
        try {
            return WebVerifiableHistoryCreator.builder()
                    .verificationMethodKeyProvider(signer)
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .updateKeys(Set.of(
                            new File(TEST_DATA_PATH_PREFIX + "public.pem") // to be able to use TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS while updating
                            //,TEST_KEY_FILES[0]
                    ))
                    .build()
                    .createDidLog(URL.of(new URI(TEST_DID_URL), null), ZonedDateTime.parse(ISO_DATE_TIME));
        } catch (Exception simplyIntolerable) {
            throw new IllegalArgumentException(simplyIntolerable);
        }
    }

    /**
     * The helper delivers an initial {@code did:webvh} DID log entry featuring the pre-rotation keys denoted by {@code nextKeys}
     *
     * @param nextKeys to be used when adding the next {@code did:webvh} DID log entry
     * @return a valid {@code did:webvh} DID log entry
     * @see #buildInitialTdwDidLogEntry(VerificationMethodKeyProvider)
     */
    protected static String buildInitialWebVerifiableHistoryDidLogEntryWithKeyPrerotation(
            Set<File> nextKeys) {
        try {
            return WebVerifiableHistoryCreator.builder()
                    // CAUTION Calling .verificationMethodKeyProvider(...) is here irrelevant thus redundant
                    .assertionMethodKeys(TEST_ASSERTION_METHOD_KEYS)
                    .authenticationKeys(TEST_AUTHENTICATION_METHOD_KEYS)
                    .nextKeys(nextKeys) // IMPORTANT denotes key pre-rotation
                    .build()
                    .createDidLog(URL.of(new URI(TEST_DID_URL), null), ZonedDateTime.parse(ISO_DATE_TIME));
        } catch (Exception simplyIntolerable) {
            throw new IllegalArgumentException(simplyIntolerable);
        }
    }

    protected static String buildTdwDidLog(VerificationMethodKeyProvider signer) {

        var updatedDidLog = new StringBuilder(buildInitialTdwDidLogEntry(signer));

        try {
            for (int i = 2; i < 5; i++) { // update DID log by adding several new entries

                // The versionTime for each log entry MUST be greater than the previous entry’s time.
                // The versionTime of the last entry MUST be earlier than the current time.
                Thread.sleep(1000);

                var nextLogEntry = DidLogUpdaterContext.builder()
                        .didMethod(DidMethodEnum.TDW_0_3) // the legacy spec. version thus not default
                        .verificationMethodKeyProvider(signer)
                        .assertionMethodKeys(Map.of("my-assert-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-0" + i)))
                        .authenticationKeys(Map.of("my-auth-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-0" + i)))
                        .build()
                        .update(updatedDidLog.toString());

                updatedDidLog.append(System.lineSeparator()).append(nextLogEntry);
            }

        } catch (Exception e) {
            fail(e);
        }

        //System.out.println(updatedDidLog);

        return updatedDidLog.toString();
    }

    protected static String buildWebVhDidLog(VerificationMethodKeyProvider signer) {

        var updatedDidLog = new StringBuilder(buildInitialWebVerifiableHistoryDidLogEntry(signer));

        try {
            for (int i = 2; i < 5; i++) { // update DID log by adding several new entries

                // The versionTime for each log entry MUST be greater than the previous entry’s time.
                // The versionTime of the last entry MUST be earlier than the current time.
                Thread.sleep(1000);

                var nextLogEntry = DidLogUpdaterContext.builder()
                        //.didMethod(DidMethodEnum.WEBVH_1_0) // default
                        .verificationMethodKeyProvider(signer)
                        .assertionMethodKeys(Map.of("my-assert-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/assert-key-01.pub"), "my-assert-key-0" + i)))
                        .authenticationKeys(Map.of("my-auth-key-0" + i, JwkUtils.loadECPublicJWKasJSON(new File("src/test/data/auth-key-01.pub"), "my-auth-key-0" + i)))
                        .build()
                        .update(updatedDidLog.toString());

                updatedDidLog.append(System.lineSeparator()).append(nextLogEntry);
            }

        } catch (Exception e) {
            fail(e);
        }

        //System.out.println(updatedDidLog);

        return updatedDidLog.toString();
    }

    protected static byte[] decodeEncodedKey(byte[] encodedKey) {
        return Arrays.copyOfRange(encodedKey, encodedKey.length - 32, encodedKey.length);
    }
}
