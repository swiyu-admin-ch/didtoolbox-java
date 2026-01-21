package ch.admin.bj.swiyu.didtoolbox.context;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.TdwCreatorTest;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryCreatorTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URL;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

@SuppressWarnings("PMD")
class DidLogCreatorStrategyTest extends AbstractUtilTestBase {

    @DisplayName("Building DID log entry for various identifierRegistryUrl variants")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testCreate(URL identifierRegistryUrl) {

        AtomicReference<String> didLogEntry = new AtomicReference<>();

        // did:tdw

        assertDoesNotThrow(() -> {
            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(DidLogCreatorContext.builder()
                    .didMethod(DidMethodEnum.TDW_0_3)
                    // the default signer (verificationMethodKeyProvider) is used
                    .forceOverwrite(true)
                    .build()
                    .create(identifierRegistryUrl)); // MUT
        });

        TdwCreatorTest.assertDidLogEntry(didLogEntry.get());

        // did:webvh

        assertDoesNotThrow(() -> {
            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(DidLogCreatorContext.builder()
                    .didMethod(DidMethodEnum.WEBVH_1_0) // default
                    // the default signer (verificationMethodKeyProvider) is used
                    .forceOverwrite(true)
                    .build()
                    .create(identifierRegistryUrl)); // MUT
        });

        WebVerifiableHistoryCreatorTest.assertDidLogEntry(didLogEntry.get());
    }
}