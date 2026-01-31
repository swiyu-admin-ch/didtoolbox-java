package ch.admin.bj.swiyu.didtoolbox.context;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.RandomEd25519KeyStore;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.model.UpdateKeysDidMethodParameter;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("PMD")
class DidLogUpdaterContextTest extends AbstractUtilTestBase {

    @DisplayName("Inducing 'Update Key Mismatch' error while updating DID log")
    @Test
    void testUpdateThrowsUpdateKeyMismatchDidLogUpdaterStrategyException() {

        // did:tdw

        var didLog = buildInitialTdwDidLogEntry(TEST_CRYPTO_SUITE_JKS);
        String finalDidLog1 = didLog;

        var illegalArgExc = assertThrowsExactly(IllegalArgumentException.class, () -> {

            DidLogUpdaterContext.builder()
                    .didMethod(DidMethodEnum.TDW_0_3) // must be set explicitly for did:tdw logs
                    // no explicit cryptographicSuite set, hence keys are generated on-the-fly
                    // CAUTION Key pre-rotation is not (yet) implemented for did:tdw
                    .nextKeyHashesDidMethodParameter(Set.of(NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public01.pem")))) // activate prerotation by adding another key for the future
                    .build()
                    .update(finalDidLog1); // MUT
        });
        assertTrue(illegalArgExc.getMessage().contains("currently not supported"));

        var exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {

            DidLogUpdaterContext.builder()
                    .didMethod(DidMethodEnum.TDW_0_3) // must be set explicitly for did:tdw logs
                    // no explicit cryptographicSuite set, hence keys are generated on-the-fly
                    .build()
                    .update(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            DidLogUpdaterContext.builder()
                    .didMethod(DidMethodEnum.TDW_0_3) // must be set explicitly for did:tdw logs
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem")))) // ...with NO matching key supplied!
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
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem")))) // ...with NO matching key supplied!
                    .build()
                    .update(finalDidLog1); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        // did:webvh

        didLog = buildInitialWebVerifiableHistoryDidLogEntry(TEST_CRYPTO_SUITE_JKS);
        String finalDidLog2 = didLog;

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {

            DidLogUpdaterContext.builder()
                    //.didMethod(DidMethodEnum.WEBVH_1_0) // default
                    // no explicit cryptographicSuite set, hence keys are generated on-the-fly
                    .build()
                    .update(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            DidLogUpdaterContext.builder()
                    //.didMethod(DidMethodEnum.WEBVH_1_0) // default
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem")))) // ...with NO matching key supplied!
                    .build()
                    .update(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        // detecting DID method

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {

            DidLogUpdaterContext.builder()
                    .didMethod(DidMethodEnum.detectDidMethod(finalDidLog2))
                    // no explicit cryptographicSuite set, hence keys are generated on-the-fly
                    .build()
                    .update(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));

        exc = assertThrowsExactly(DidLogUpdaterStrategyException.class, () -> {
            DidLogUpdaterContext.builder()
                    .didMethod(DidMethodEnum.detectDidMethod(finalDidLog2))
                    .cryptographicSuite(TEST_CRYPTO_SUITE) // using another verification key provider...
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem")))) // ...with NO matching key supplied!
                    .build()
                    .update(finalDidLog2); // MUT
        });
        assertTrue(exc.getMessage().contains("Update key mismatch"));
    }

    @DisplayName("Multiple updates of DID log using various pre-rotation keys")
    @Test
    void testMultipleUpdateDidLogWithKeyPrerotation() {

        assertDoesNotThrow(() -> {

            // build initial DID log entry
            var didLog = new StringBuilder(
                    // initial (by default, did:webvh:1.0) DID log entry (featuring a pre-rotation key)
                    DidLogCreatorContext.builder()
                            .cryptographicSuite(RandomEd25519KeyStore.cryptographicSuite())
                            // IMPORTANT Calling this method activates key pre-rotation
                            .nextKeyHashesDidMethodParameter(Set.of(
                                    // get a whole another pre-rotation key to be used when building the next DID log entry.
                                    // Bear in mind, after the key store "rotation", all its (static) helpers "point" to the next/another key in the store
                                    NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                                    // REMINDER Indeed, you may keep adding more keys this way - beware that some of them
                                    //          MUST entirely match the "updateKeys" values in the DID log next entry
                                    //,NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                                    //,NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                            ))
                            // Forced to avoid error: "The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged: .didtoolbox/auth-key-01"
                            .forceOverwrite(true)
                            .build()
                            .create(URL.of(new URI(TEST_DID_URL), null)) // should not throw DidLogCreatorStrategyException
            ).append(System.lineSeparator());

            assertTrue(JsonParser.parseString(didLog.toString()).getAsJsonObject().get("parameters").getAsJsonObject().has("updateKeys")); // denotes key pre-rotation

            // Update the DID log by adding as many entries as there are keys in the store.
            // Keep "rotating" (pre-rotation) keys while updating
            var i = 0;
            while (i++ < RandomEd25519KeyStore.getCapacity()) {

                didLog.append(
                        // next DID log entry
                        DidLogUpdaterContext.builder()
                                // switch to the key defined by the "nextKeyHashes" from the previous entry (the key store is already "rotated" earlier)
                                .cryptographicSuite(RandomEd25519KeyStore.cryptographicSuite())
                                // REMINDER .didtoolbox directory was created previously while building the initial DID log entry (thanks to .forceOverwrite(true))
                                .assertionMethodKeys(Map.of("my-assert-key-0" + i, JwkUtils.loadECPublicJWKasJSON(Path.of(".didtoolbox/assert-key-01.pub"), "my-assert-key-0" + i))).authenticationKeys(Map.of("my-auth-key-0" + i, JwkUtils.loadECPublicJWKasJSON(Path.of(".didtoolbox/auth-key-01.pub"), "my-auth-key-0" + i)))
                                // Prepare ("rotate" to) another pre-rotation key to be used when building the next DID log entry
                                .nextKeyHashesDidMethodParameter(Set.of(
                                        // Bear in mind, after the key store "rotation", all its (static) helpers "point" to the next/another key in the store
                                        //RandomEd25519KeyStore.rotate().asNextKeyHashesDidMethodParameter()
                                        NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                                        // REMINDER Indeed, you may keep adding more keys this way - beware that some of them
                                        //          MUST entirely match the "updateKeys" values in the DID log next entry
                                        //,NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                                        //,NextKeyHashesDidMethodParameter.of(RandomEd25519KeyStore.rotate().getPublicKey())
                                ))
                                .build()
                                .update(didLog.toString()) // should not throw DidLogUpdaterStrategyException
                ).append(System.lineSeparator());
            }
        });
    }
}