package ch.admin.bj.swiyu.didtoolbox.context;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CreateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.did.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogDeactivatorContext;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogDeactivatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.model.DidMethodEnum;
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
            DidLogDeactivatorContext.builder(DidMethodEnum.TDW_0_3, new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                    .build()
                    .deactivate(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder(DidMethodEnum.TDW_0_3, TEST_CRYPTO_SUITE) // using another verification key provider...
                    .build()
                    .deactivate(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        // detecting DID method

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder(DidMethodEnum.detectDidMethod(finalDidLog1), new EdDsaJcs2022VcDataIntegrityCryptographicSuite()) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .deactivate(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder(DidMethodEnum.detectDidMethod(finalDidLog1), TEST_CRYPTO_SUITE) // using another verification key provider...
                    .build()
                    .deactivate(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        // did:webvh

        didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS);
        String finalDidLog2 = didLog;

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder(DidMethodEnum.WEBVH_1_0, new EdDsaJcs2022VcDataIntegrityCryptographicSuite())
                    .build()
                    .deactivate(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder(DidMethodEnum.WEBVH_1_0,TEST_CRYPTO_SUITE) // using another verification key provider...
                    .build()
                    .deactivate(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        // detecting DID method

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder(DidMethodEnum.detectDidMethod(finalDidLog2), new EdDsaJcs2022VcDataIntegrityCryptographicSuite()) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .build()
                    .deactivate(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));

        exc = assertThrowsExactly(DidLogDeactivatorStrategyException.class, () -> {
            DidLogDeactivatorContext.builder(DidMethodEnum.detectDidMethod(finalDidLog2), new EdDsaJcs2022VcDataIntegrityCryptographicSuite()) // no explicit verificationMethodKeyProvider, hence keys are generated on-the-fly
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .build()
                    .deactivate(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Deactivation key mismatch"));
    }
}