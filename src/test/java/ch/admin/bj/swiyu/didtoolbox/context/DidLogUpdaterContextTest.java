package ch.admin.bj.swiyu.didtoolbox.context;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("PMD")
class DidLogUpdaterContextTest extends AbstractUtilTestBase {

    @Test
    void testUpdateThrowsUpdateKeyMismatchDidLogUpdaterStrategyException() {

        // did:tdw

        var didLog = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE_JKS);
        String finalDidLog1 = didLog;

        var exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {

            DidLogUpdaterContext.builder()
                    .didMethod(DidMethodEnum.TDW_0_3) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .update(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            DidLogUpdaterContext.builder()
                    .didMethod(DidMethodEnum.TDW_0_3)
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .updateKeys(Set.of(new File("src/test/data/public.pem"))) // ...with NO matching key supplied!
                    .build()
                    .update(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        // detecting DID method

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {

            DidLogUpdaterContext.builder()
                    .didMethod(DidMethodEnum.detectDidMethod(finalDidLog1)) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .update(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            DidLogUpdaterContext.builder()
                    .didMethod(DidMethodEnum.detectDidMethod(finalDidLog1))
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .updateKeys(Set.of(new File("src/test/data/public.pem"))) // ...with NO matching key supplied!
                    .build()
                    .update(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        // did:webvh

        didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS);
        String finalDidLog2 = didLog;

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {

            DidLogUpdaterContext.builder()
                    //.didMethod(DidMethodEnum.WEBVH_1_0) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .update(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            DidLogUpdaterContext.builder()
                    //.didMethod(DidMethodEnum.WEBVH_1_0)
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .updateKeys(Set.of(new File("src/test/data/public.pem"))) // ...with NO matching key supplied!
                    .build()
                    .update(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        // detecting DID method

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {

            DidLogUpdaterContext.builder()
                    .didMethod(DidMethodEnum.detectDidMethod(finalDidLog2)) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .update(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            DidLogUpdaterContext.builder()
                    .didMethod(DidMethodEnum.detectDidMethod(finalDidLog2))
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .updateKeys(Set.of(new File("src/test/data/public.pem"))) // ...with NO matching key supplied!
                    .build()
                    .update(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));
    }
}