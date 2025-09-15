package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.strategy.DidLogDeactivatorContext;
import ch.admin.bj.swiyu.didtoolbox.strategy.DidLogDeactivatorStrategyException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DidLogDeactivatorStrategyTest extends AbstractUtilTestBase {

    @Test
    void testDeactivateThrowsDeactivationKeyMismatchDidLogDeactivatorStrategyException() {

        // did:tdw

        var didLog = buildInitialTdwDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS);
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
                    .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER) // using another verification key provider...
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
                    .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER) // using another verification key provider...
                    .build()
                    .deactivate(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        // did:webvh

        didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_VERIFICATION_METHOD_KEY_PROVIDER_JKS);
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
                    .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER) // using another verification key provider...
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
                    .verificationMethodKeyProvider(TEST_VERIFICATION_METHOD_KEY_PROVIDER) // using another verification key provider...
                    .build()
                    .deactivate(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));
    }
}