package ch.admin.bj.swiyu.didtoolbox.context;

import ch.admin.bj.swiyu.didtoolbox.AbstractUtilTestBase;
import ch.admin.bj.swiyu.didtoolbox.TdwCreatorTest;
import ch.admin.bj.swiyu.didtoolbox.model.DidMethodEnum;
import ch.admin.bj.swiyu.didtoolbox.model.NamedDidMethodParameters;
import ch.admin.bj.swiyu.didtoolbox.model.NextKeyHashesDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.model.UpdateKeysDidMethodParameter;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryCreatorTest;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URL;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("PMD")
class DidLogCreatorStrategyTest extends AbstractUtilTestBase {

    @DisplayName("Building DID log entry for various identifierRegistryUrl variants")
    @ParameterizedTest(name = "For identifierRegistryUrl: {0}")
    @MethodSource("identifierRegistryUrl")
    public void testCreate(URL identifierRegistryUrl) {

        AtomicReference<String> didLogEntry = new AtomicReference<>();

        // did:tdw

        assertDoesNotThrow(() -> {

            // NOTE that all keys will all be generated here as well, as the default cryptographicSuite is used
            var ctxBuilder = DidLogCreatorContext.builder()
                    .didMethod(DidMethodEnum.TDW_0_3) // must be set explicitly for did:tdw logs
                    // the default cryptographicSuite is used, with generated key pair
                    .forceOverwrite(true)
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem")))); // add another value "updateKeys" param

            didLogEntry.set(ctxBuilder.build().create(identifierRegistryUrl)); // MUT

            TdwCreatorTest.assertDidLogEntry(didLogEntry.get());

            var params = JsonParser.parseString(didLogEntry.get()).getAsJsonArray().get(2).getAsJsonObject();
            assertFalse(params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().isEmpty());
            assertEquals(2, params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().size()); // Effectively, it is only 2 distinct keys

            var exc = assertThrowsExactly(IllegalArgumentException.class, () -> {
                // CAUTION Key pre-rotation is not (yet) implemented for did:tdw
                ctxBuilder.nextKeyHashesDidMethodParameter(Set.of(NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public01.pem")))) // activate prerotation by adding another key for the future
                        .build()
                        .create(identifierRegistryUrl); // MUT
            });
            assertTrue(exc.getMessage().contains("not (yet) implemented"));
        });

        // did:webvh

        assertDoesNotThrow(() -> {
            // Note that all keys will all be generated here as well, as the default Ed25519SignerVerifier constructor is used implicitly
            didLogEntry.set(DidLogCreatorContext.builder()
                    //.didMethod(DidMethodEnum.WEBVH_1_0) // default
                    // the default cryptographicSuite is used, with generated key pair
                    .updateKeysDidMethodParameter(Set.of(UpdateKeysDidMethodParameter.of(Path.of("src/test/data/public.pem")))) // add another value "updateKeys" param
                    .nextKeyHashesDidMethodParameter(Set.of(NextKeyHashesDidMethodParameter.of(Path.of("src/test/data/public01.pem")))) // activate prerotation by adding another key for the future
                    .forceOverwrite(true)
                    .build()
                    .create(identifierRegistryUrl)); // MUT
        });

        WebVerifiableHistoryCreatorTest.assertDidLogEntry(didLogEntry.get());

        var params = JsonParser.parseString(didLogEntry.get()).getAsJsonObject().get("parameters").getAsJsonObject();
        assertFalse(params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().isEmpty());
        assertEquals(2, params.get(NamedDidMethodParameters.UPDATE_KEYS).getAsJsonArray().size()); // Effectively, it is only 2 distinct keys

        assertFalse(params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().isEmpty());
        assertEquals(1, params.get(NamedDidMethodParameters.NEXT_KEY_HASHES).getAsJsonArray().size()); // Effectively, it is only 2 distinct keys
    }
}