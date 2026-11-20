package ch.admin.bj.swiyu.didtoolbox.cryptography.primus;

import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreInitializationException;
import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreLoader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.ClearEnvironmentVariable;
import org.junitpioneer.jupiter.SetEnvironmentVariable;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatcher;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

import static ch.admin.bj.swiyu.didtoolbox.did.AbstractUtilTestBase.TEST_DATA_PATH_PREFIX;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@TestInstance(TestInstance.Lifecycle.PER_METHOD)
@Execution(ExecutionMode.CONCURRENT)
@SuppressWarnings("PMD")
public class SecurosysPrimusKeyStoreLoaderTest {

    @BeforeEach
    void beforeEach() {
        Security.removeProvider("SecurosysPrimusXSeries");
    }

    @AfterEach
    void afterEach() {
        Security.removeProvider("SecurosysPrimusXSeries");
    }

    //@Test
    @Execution(ExecutionMode.CONCURRENT)
    @SetEnvironmentVariable(key = "SECUROSYS_PRIMUS_HOST", value = "unknown")
    @SetEnvironmentVariable(key = "SECUROSYS_PRIMUS_PORT", value = "2300")
    @SetEnvironmentVariable(key = "SECUROSYS_PRIMUS_USER", value = "unknown")
    @SetEnvironmentVariable(key = "SECUROSYS_PRIMUS_PASSWORD", value = "unknown")
    public void testNewSecurosysPrimusKeyStoreThrowsRuntimeException() {

        assertNotNull((System.getenv(PrimusKeyStoreLoader.SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_HOST.name())));
        assertNotNull((System.getenv(PrimusKeyStoreLoader.SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PORT.name())));
        assertNotNull((System.getenv(PrimusKeyStoreLoader.SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_USER.name())));
        assertNotNull((System.getenv(PrimusKeyStoreLoader.SecurosysPrimusEnvironment.SECUROSYS_PRIMUS_PASSWORD.name())));

        var exc = assertThrows(Exception.class, () -> { // actually, it is: com.securosys.primus.jce.PrimusLoginException
            var loader = new PrimusKeyStoreLoader(null);
        });
        assertEquals("com.securosys.primus.jce.PrimusLoginException", exc.getClass().getName());
        assertNotNull(Security.getProvider("SecurosysPrimusXSeries"));
        assertTrue(exc.getMessage().contains("login by properties failed: com.securosys.primus.jce.PrimusLoginException: login failed into HSM unknown:2300:unknown: connectivity problem: com.securosys.primus.jce.broker.AsyncBrokerException: com.securosys.primus.jce.transport.TransportException: unknown:2300:unknown: java.net.UnknownHostException: unknown: nodename nor servname provided, or not known"));
    }

    //@Test
    @Execution(ExecutionMode.CONCURRENT)
    public void testNewSecurosysPrimusKeyStoreThrowsRuntimeException2() {

        var exc = assertThrows(Exception.class, () -> { // actually, it is: com.securosys.primus.jce.PrimusLoginException
            var loader = new PrimusKeyStoreLoader(new File("src/test/data/com.securosys.primus.jce.credentials.properties"));
        });
        assertEquals("com.securosys.primus.jce.PrimusLoginException", exc.getClass().getName());
        assertNotNull(Security.getProvider("SecurosysPrimusXSeries"));
        assertTrue(exc.getMessage().contains("login by properties failed: com.securosys.primus.jce.PrimusLoginException: login failed into HSM unknown:2300:unknown: connectivity problem: com.securosys.primus.jce.broker.AsyncBrokerException: com.securosys.primus.jce.transport.TransportException: unknown:2300:unknown: java.net.UnknownHostException: unknown: nodename nor servname provided, or not known"));
    }

    //@Test
    @Execution(ExecutionMode.CONCURRENT)
    public void testNewSecurosysPrimusKeyStoreThrowsRuntimeException3() {

        var exc = assertThrows(Exception.class, () -> { // actually, it is: com.securosys.primus.jce.PrimusLoginException
            var loader = new PrimusKeyStoreLoader("unknown", 2300, "unknown", "unknown".toCharArray());
        });
        assertEquals("com.securosys.primus.jce.PrimusLoginException", exc.getClass().getName());
        assertNotNull(Security.getProvider("SecurosysPrimusXSeries"));
        assertTrue(exc.getMessage().contains("login by properties failed: com.securosys.primus.jce.PrimusLoginException: login failed into HSM unknown:2300:unknown: connectivity problem: com.securosys.primus.jce.broker.AsyncBrokerException: com.securosys.primus.jce.transport.TransportException: unknown:2300:unknown: java.net.UnknownHostException: unknown: nodename nor servname provided, or not known"));
    }


    KeyStore primusKeyStore = mock(KeyStore.class);
    // Class used to inject a custom keystore.
    class TestPrimusKeyStoreLoader extends PrimusKeyStoreLoader {
        public TestPrimusKeyStoreLoader() throws PrimusKeyStoreInitializationException {
            super();
        }

        public TestPrimusKeyStoreLoader(File credentials) throws CertificateException, IOException, NoSuchAlgorithmException, PrimusKeyStoreInitializationException {
            super(credentials);
        }

        public TestPrimusKeyStoreLoader(String host, int port, String user, char[] password) throws CertificateException, IOException, NoSuchAlgorithmException, PrimusKeyStoreInitializationException {
            super(host, port, user, password);
        }

        @Override
        protected KeyStore initKeyStore() throws PrimusKeyStoreInitializationException {
            return primusKeyStore;
        }
    }

    @Test
    void testConstructor_keyStoreNotNull_success() throws IOException {
        var loader =  assertDoesNotThrow(() -> new TestPrimusKeyStoreLoader());
        assertNotNull(loader.getKeyStore());
    }

    @Test
    void testConstructor_withConfigFile_success() throws IOException, CertificateException, NoSuchAlgorithmException {
        ArgumentMatcher<InputStream> streamMatcher = (inputStream) -> {
            try {
                var resultString = new String(inputStream.readAllBytes(), Charset.defaultCharset());
                // Check that arguments from config were provided
                assertTrue(resultString.contains("all_params_host"));
                assertTrue(resultString.contains("65000"));
                assertTrue(resultString.contains("all_params_user"));
                assertTrue(resultString.contains("all_params_password"));
                return true;
            } catch (IOException e) {
                return false;
            }
        };
        doNothing().when(primusKeyStore).load(argThat(streamMatcher), isNull());
        File configFile = new File(TEST_DATA_PATH_PREFIX + "primus_configurations/AllParams");
        var loader =  assertDoesNotThrow(() -> new TestPrimusKeyStoreLoader(configFile));
        assertNotNull(loader);
    }

    @ParameterizedTest
    @ValueSource(strings = {"MissingHost", "MissingPort", "MissingUser", "MissingPassword"})
    void testConstructor_withMissingConfigInFile_failure(String config) {
        ArgumentCaptor<InputStream> streamCaptor = ArgumentCaptor.forClass(InputStream.class);
        File configFile = new File(TEST_DATA_PATH_PREFIX + "primus_configurations/" + config);
        var e = assertThrowsExactly(PrimusKeyStoreInitializationException.class, () -> new TestPrimusKeyStoreLoader(configFile));
        assertTrue(e.getMessage().contains("You may supply it"));
    }

    @Test
    void testPrimusEnvironmentBuild() throws IOException {
        var host = "example_host";
        var port = 1234;
        var user = "example_user";
        var password = "example_password";

        var expected = """
                com.securosys.primus.jce.credentials.host=example_host
                com.securosys.primus.jce.credentials.port=1234
                com.securosys.primus.jce.credentials.user=example_user
                com.securosys.primus.jce.credentials.password=example_password
                """;

        var passwordArray = password.toCharArray();
        var byteStream = assertDoesNotThrow(() -> PrimusKeyStoreLoader.SecurosysPrimusEnvironment.build(host, port, user, passwordArray));
        var resultString = new String(byteStream, Charset.defaultCharset());
        assertTrue(expected.trim().equals(resultString.trim()), "Expected:\n" + expected + "\n but got instead:\n" + resultString);
        assertNotEquals(password, new String(passwordArray)); // expect password to have been cleaned
    }

    private static final String ALIAS = "my-alias";

    private static File credentialsFileWithPort(Path dir, String port) throws IOException {
        return Files.writeString(dir.resolve("credentials"), """
                securosys_primus_host=file_host
                securosys_primus_port=%s
                securosys_primus_user=file_user
                securosys_primus_password=file_password
                """.formatted(port)).toFile();
    }

    private AtomicReference<Properties> captureLoadedCredentials() throws IOException, GeneralSecurityException {
        var loaded = new AtomicReference<Properties>();
        // CAUTION The stream must be consumed while load() runs, as its backing array gets wiped right after
        doAnswer(invocation -> {
            var properties = new Properties();
            properties.load(invocation.<InputStream>getArgument(0));
            loaded.set(properties);
            return null;
        }).when(primusKeyStore).load(any(InputStream.class), isNull());
        return loaded;
    }

    private static KeyPair generateP256KeyPair() throws GeneralSecurityException {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private void stubStoredKeyPair(KeyPair keyPair) throws GeneralSecurityException {
        var certificate = mock(Certificate.class);
        when(certificate.getPublicKey()).thenReturn(keyPair.getPublic());
        when(primusKeyStore.isKeyEntry(ALIAS)).thenReturn(true);
        when(primusKeyStore.getKey(eq(ALIAS), any())).thenReturn(keyPair.getPrivate());
        when(primusKeyStore.getCertificate(ALIAS)).thenReturn(certificate);
        when(primusKeyStore.getProvider()).thenReturn(KeyFactory.getInstance("EC").getProvider());
    }

    @ParameterizedTest(name = "port={0}")
    @CsvSource({"not-a-port, port is invalid", "-1, port cannot be resolved"})
    @ClearEnvironmentVariable(key = "SECUROSYS_PRIMUS_PORT")
    void testConstructor_withIllegalPort_failure(String port, String expectedMessagePart, @TempDir Path tempDir) throws Exception {
        var credentials = credentialsFileWithPort(tempDir, port);

        var e = assertThrowsExactly(PrimusKeyStoreInitializationException.class, () -> new TestPrimusKeyStoreLoader(credentials));

        assertTrue(e.getMessage().contains(expectedMessagePart));
        verify(primusKeyStore, never()).load(any(InputStream.class), any());
    }

    @Test
    @ClearEnvironmentVariable(key = "SECUROSYS_PRIMUS_PORT")
    void testConstructor_withHighestValidPort_success(@TempDir Path tempDir) throws Exception {
        var loaded = captureLoadedCredentials();

        new TestPrimusKeyStoreLoader(credentialsFileWithPort(tempDir, "65535"));

        assertEquals("65535", loaded.get().getProperty("com.securosys.primus.jce.credentials.port"));
    }

    @Test
    @SetEnvironmentVariable(key = "SECUROSYS_PRIMUS_HOST", value = "env_host")
    @SetEnvironmentVariable(key = "SECUROSYS_PRIMUS_PORT", value = "2300")
    @SetEnvironmentVariable(key = "SECUROSYS_PRIMUS_USER", value = "env_user")
    @SetEnvironmentVariable(key = "SECUROSYS_PRIMUS_PASSWORD", value = "env_password")
    void testConstructor_environmentVariablesWinOverConfigFile() throws Exception {
        var loaded = captureLoadedCredentials();

        new TestPrimusKeyStoreLoader(new File(TEST_DATA_PATH_PREFIX + "primus_configurations/AllParams"));

        assertEquals("env_host", loaded.get().getProperty("com.securosys.primus.jce.credentials.host"));
        assertEquals("2300", loaded.get().getProperty("com.securosys.primus.jce.credentials.port"));
        assertEquals("env_user", loaded.get().getProperty("com.securosys.primus.jce.credentials.user"));
        assertEquals("env_password", loaded.get().getProperty("com.securosys.primus.jce.credentials.password"));
    }

    @Test
    @ClearEnvironmentVariable(key = "SECUROSYS_PRIMUS_HOST")
    void testConstructor_withNullCredentialsAndNoEnvironment_failure() {
        var e = assertThrowsExactly(PrimusKeyStoreInitializationException.class, () -> new TestPrimusKeyStoreLoader(null));

        assertTrue(e.getMessage().contains("host cannot be resolved"));
    }

    @Test
    void loadKeyPair_aliasIsNotKeyEntry_throwsKeyExceptionWithoutFetchingKey() throws Exception {
        when(primusKeyStore.isKeyEntry(ALIAS)).thenReturn(false);
        var loader = new TestPrimusKeyStoreLoader();

        var e = assertThrowsExactly(KeyException.class, () -> loader.loadKeyPair(ALIAS, null));

        assertTrue(e.getMessage().contains(ALIAS));
        verify(primusKeyStore, never()).getKey(any(), any());
    }

    // A null password must reach getKey as null, not as an empty array (HSM keys without a per-key password),
    // and a non-null password must be the very same array, left unmodified, because the caller wipes it
    @ParameterizedTest(name = "password={0}")
    @NullSource
    @ValueSource(strings = "secret")
    void loadKeyPair_withStoredP256KeyPair_returnsKeysUsingSuppliedPasswordUnchanged(String passwordValue) throws Exception {
        var keyPair = generateP256KeyPair();
        stubStoredKeyPair(keyPair);
        var password = passwordValue == null ? null : passwordValue.toCharArray();

        var loaded = new TestPrimusKeyStoreLoader().loadKeyPair(ALIAS, password);

        assertSame(keyPair.getPrivate(), loaded.getPrivate());
        assertEquals(keyPair.getPublic(), loaded.getPublic());
        verify(primusKeyStore).getKey(eq(ALIAS), same(password));
        assertArrayEquals(passwordValue == null ? null : passwordValue.toCharArray(), password);
    }

    @Test
    void loadKeyPair_getKeyReturnsNull_throwsKeyException() throws Exception {
        stubStoredKeyPair(generateP256KeyPair()); // CAUTION The certificate must be present, as its absence would also cause a KeyException
        when(primusKeyStore.getKey(ALIAS, null)).thenReturn(null);
        var loader = new TestPrimusKeyStoreLoader();

        var e = assertThrowsExactly(KeyException.class, () -> loader.loadKeyPair(ALIAS, null));

        assertTrue(e.getMessage().contains("does not identify a key-related entry"));
        assertTrue(e.getMessage().contains(ALIAS));
        verify(primusKeyStore, never()).getCertificate(any());
    }

    @Test
    void loadKeyPair_getCertificateReturnsNull_throwsKeyException() throws Exception {
        stubStoredKeyPair(generateP256KeyPair());
        when(primusKeyStore.getCertificate(ALIAS)).thenReturn(null);
        var loader = new TestPrimusKeyStoreLoader();

        var e = assertThrowsExactly(KeyException.class, () -> loader.loadKeyPair(ALIAS, null));

        assertTrue(e.getMessage().contains("does not contain a certificate"));
        assertTrue(e.getMessage().contains(ALIAS));
    }
}