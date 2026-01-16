package ch.admin.bj.swiyu.didtoolbox.context;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("PMD")
class DidLogDeactivatorContextTest extends AbstractUtilTestBase {

    @Test
    void testDeactivateThrowsDeactivationKeyMismatchDidLogDeactivatorStrategyException() {

        // did:tdw

        var didLog = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE_JKS);
        String finalDidLog1 = didLog;

        var exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder()
                    .didMethod(DidMethodEnum.TDW_0_3) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .deactivate(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder()
                    .didMethod(DidMethodEnum.TDW_0_3)
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .build()
                    .deactivate(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        // detecting DID method

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder()
                    .didMethod(DidMethodEnum.detectDidMethod(finalDidLog1)) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .deactivate(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder()
                    .didMethod(DidMethodEnum.detectDidMethod(finalDidLog1))
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .build()
                    .deactivate(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        // did:webvh

        didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS);
        String finalDidLog2 = didLog;

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder()
                    // default: .didMethod(DidMethodEnum.WEBVH_1_0) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .deactivate(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder()
                    // default: .didMethod(DidMethodEnum.WEBVH_1_0)
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .build()
                    .deactivate(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        // detecting DID method

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder()
                    .didMethod(DidMethodEnum.detectDidMethod(finalDidLog2)) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .deactivate(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder()
                    .didMethod(DidMethodEnum.detectDidMethod(finalDidLog2)) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .build()
                    .deactivate(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));
    }
}