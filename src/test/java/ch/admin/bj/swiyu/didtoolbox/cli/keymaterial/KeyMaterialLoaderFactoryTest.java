package ch.admin.bj.swiyu.didtoolbox.cli.keymaterial;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CommandParameterNames;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CreateProofOfPossessionCommand;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.DeactivateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.UpdateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreLoader;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.AbstractUtilTestBase;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.security.KeyException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("PMD")
class KeyMaterialLoaderFactoryTest extends AbstractUtilTestBase {

    private static final String PRIMUS_KEY_ALIAS = "alias";

    @Test
    void from_noKeySource_isEmpty() {
        assertTrue(new UpdateDidLogCommand().keyMaterialLoader().isEmpty());
        assertTrue(new CreateProofOfPossessionCommand().keyMaterialLoader().isEmpty());
    }

    @Test
    void from_pem_returnsPemLoader() {
        var command = new DeactivateDidLogCommand();
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem");

        var loader = command.keyMaterialLoader().orElseThrow();

        assertInstanceOf(PemKeyMaterialLoader.class, loader);
        assertDoesNotThrow(() -> assertEquals(
                TEST_CRYPTO_SUITE_JKS.getVerificationKeyMultibase(), // "private.pem" matches "myalias" key from "mykeystore.jks"
                loader.loadCryptographicSuite().getVerificationKeyMultibase()));
    }

    @Test
    void from_jks_returnsJksLoader() {
        var command = new DeactivateDidLogCommand();
        command.jksFile = new File(TEST_DATA_PATH_PREFIX + "mykeystore.jks");
        command.jksPassword = "changeit";
        command.jksAlias = "myalias";

        var loader = command.keyMaterialLoader().orElseThrow();

        assertInstanceOf(JksKeyMaterialLoader.class, loader);
        assertDoesNotThrow(() -> assertEquals(
                TEST_CRYPTO_SUITE_JKS.getVerificationKeyMultibase(),
                loader.loadCryptographicSuite().getVerificationKeyMultibase()));
        // signing PoP JWTs using JKS is not supported
        assertThrowsExactly(UnsupportedOperationException.class, () -> loader.loadProofOfPossessionSigner("kid"));
    }

    @Test
    void from_incompleteJks_isEmpty() {
        var command = new DeactivateDidLogCommand();
        command.jksFile = new File(TEST_DATA_PATH_PREFIX + "mykeystore.jks"); // alias missing

        assertTrue(command.keyMaterialLoader().isEmpty());
    }

    @Test
    void from_primus_returnsPrimusLoaderPassingAliasAndPassword() throws Exception {
        var seenPassword = new AtomicReference<char[]>();
        var primus = mock(PrimusKeyStoreLoader.class);
        // CAUTION The password must be copied while loadKeyPair runs, as the loader wipes it right after
        when(primus.loadKeyPair(eq(PRIMUS_KEY_ALIAS), any())).thenAnswer(invocation -> {
            char[] password = invocation.getArgument(1);
            seenPassword.set(password == null ? null : password.clone());
            throw new KeyException("no such key");
        });

        var command = new DeactivateDidLogCommand();
        command.securosysPrimusKeyStoreLoader = primus;
        command.primusKeyAlias = PRIMUS_KEY_ALIAS;
        command.primusKeyPassword = "secret";

        var loader = command.keyMaterialLoader().orElseThrow();

        assertInstanceOf(PrimusKeyMaterialLoader.class, loader);
        assertThrowsExactly(VcDataIntegrityCryptographicSuiteException.class, loader::loadCryptographicSuite);
        assertArrayEquals("secret".toCharArray(), seenPassword.get());

        seenPassword.set(null);
        var popCommand = new CreateProofOfPossessionCommand();
        popCommand.securosysPrimusKeyStoreLoader = primus;
        popCommand.primusKeyAlias = PRIMUS_KEY_ALIAS;
        popCommand.primusKeyPassword = "secret";

        var popLoader = popCommand.keyMaterialLoader().orElseThrow();

        assertInstanceOf(PrimusKeyMaterialLoader.class, popLoader);
        assertThrowsExactly(KeyException.class, () -> popLoader.loadProofOfPossessionSigner("kid"));
        assertArrayEquals("secret".toCharArray(), seenPassword.get());
    }

    static Stream<Arguments> incompletePrimusSources() {
        return Stream.of(
                Arguments.of("credentials without alias", mock(PrimusKeyStoreLoader.class), null),
                Arguments.of("alias without credentials", null, PRIMUS_KEY_ALIAS));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("incompletePrimusSources")
    void from_incompletePrimus_isEmpty(String description, PrimusKeyStoreLoader primusLoader, String alias) {
        var command = new DeactivateDidLogCommand();
        command.securosysPrimusKeyStoreLoader = primusLoader;
        command.primusKeyAlias = alias;

        assertTrue(command.keyMaterialLoader().isEmpty());
    }

    @Test
    void from_popPem_returnsPemLoader() {
        var command = new CreateProofOfPossessionCommand();
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem");

        var loader = command.keyMaterialLoader().orElseThrow();

        assertInstanceOf(PemKeyMaterialLoader.class, loader);
        assertDoesNotThrow(() -> assertEquals("my-kid", loader.loadProofOfPossessionSigner("my-kid").getKid()));
    }

    // A Primus source always, plus the higher-ranked PEM and/or JKS sources on demand
    private static DeactivateDidLogCommand commandWithPrimusAnd(boolean withPem, boolean withJks) {
        var command = new DeactivateDidLogCommand();
        if (withPem) {
            command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem");
        }
        if (withJks) {
            command.jksFile = new File(TEST_DATA_PATH_PREFIX + "mykeystore.jks");
            command.jksPassword = "changeit";
            command.jksAlias = "myalias";
        }
        command.securosysPrimusKeyStoreLoader = mock(PrimusKeyStoreLoader.class);
        command.primusKeyAlias = PRIMUS_KEY_ALIAS;
        return command;
    }

    @Test
    void keyMaterialLoader_allKeySourcesSupplied_prefersPemThenJksThenPrimus() {
        assertInstanceOf(PemKeyMaterialLoader.class, commandWithPrimusAnd(true, true).keyMaterialLoader().orElseThrow());
        assertInstanceOf(JksKeyMaterialLoader.class, commandWithPrimusAnd(false, true).keyMaterialLoader().orElseThrow());
        assertInstanceOf(PrimusKeyMaterialLoader.class, commandWithPrimusAnd(false, false).keyMaterialLoader().orElseThrow());
    }

    @Test
    void keyMaterialLoader_popPemAndPrimusSupplied_prefersPem() {
        var command = new CreateProofOfPossessionCommand();
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem");
        command.securosysPrimusKeyStoreLoader = mock(PrimusKeyStoreLoader.class);
        command.primusKeyAlias = PRIMUS_KEY_ALIAS;

        assertInstanceOf(PemKeyMaterialLoader.class, command.keyMaterialLoader().orElseThrow());
    }

    @Test
    void keyMaterialLoader_popJksOptionsSupplied_rejectedWhileParsingLeavingNoLoader() {
        // The command declares no JKS parameters at all, so the loader cannot be fed any other way than via the command line
        var command = new CreateProofOfPossessionCommand();
        var jCommander = JCommander.newBuilder()
                .addCommand(CreateProofOfPossessionCommand.COMMAND_NAME, command)
                .build();

        var exc = assertThrowsExactly(ParameterException.class, () -> jCommander.parse(
                CreateProofOfPossessionCommand.COMMAND_NAME,
                CommandParameterNames.PARAM_NAME_LONG_NONCE, "my_nonce",
                CommandParameterNames.PARAM_NAME_LONG_KID, "my_kid",
                CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, TEST_DATA_PATH_PREFIX + "README.md",
                CommandParameterNames.PARAM_NAME_LONG_JKS_FILE, TEST_DATA_PATH_PREFIX + "mykeystore.jks",
                CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS, "myalias"));

        assertTrue(exc.getMessage().contains(CommandParameterNames.PARAM_NAME_LONG_JKS_FILE), exc.getMessage());
        assertTrue(command.keyMaterialLoader().isEmpty());
    }
}
