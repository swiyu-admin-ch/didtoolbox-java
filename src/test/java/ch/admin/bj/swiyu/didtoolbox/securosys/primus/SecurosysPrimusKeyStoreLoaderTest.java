package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junitpioneer.jupiter.SetEnvironmentVariable;

import java.io.File;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_METHOD)
@Execution(ExecutionMode.CONCURRENT)
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
            var loader = new PrimusKeyStoreLoader("unknown", 2300, "unknown", "unknown");
        });
        assertEquals("com.securosys.primus.jce.PrimusLoginException", exc.getClass().getName());
        assertNotNull(Security.getProvider("SecurosysPrimusXSeries"));
        assertTrue(exc.getMessage().contains("login by properties failed: com.securosys.primus.jce.PrimusLoginException: login failed into HSM unknown:2300:unknown: connectivity problem: com.securosys.primus.jce.broker.AsyncBrokerException: com.securosys.primus.jce.transport.TransportException: unknown:2300:unknown: java.net.UnknownHostException: unknown: nodename nor servname provided, or not known"));
    }
}