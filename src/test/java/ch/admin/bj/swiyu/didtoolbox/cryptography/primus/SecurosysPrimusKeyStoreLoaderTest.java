package ch.admin.bj.swiyu.didtoolbox.cryptography.primus;

import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreInitializationException;
import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreLoader;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junitpioneer.jupiter.SetEnvironmentVariable;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatcher;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateException;

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
}