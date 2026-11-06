package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CreateProofOfPossessionCommand;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.DeactivateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.UpdateDidLogCommand;
import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreLoader;
import ch.admin.bj.swiyu.didtoolbox.did.AbstractUtilTestBase;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

@SuppressWarnings("PMD")
class KeyMaterialLoaderFactoryTest extends AbstractUtilTestBase {

    @Test
    void from_noKeySource_isEmpty() {
        assertTrue(KeyMaterialLoaderFactory.from(new UpdateDidLogCommand()).isEmpty());
        assertTrue(KeyMaterialLoaderFactory.from(new CreateProofOfPossessionCommand()).isEmpty());
    }

    @Test
    void from_pem_returnsPemLoader() {
        var command = new DeactivateDidLogCommand();
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem");

        var loader = KeyMaterialLoaderFactory.from(command).orElseThrow();

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

        var loader = KeyMaterialLoaderFactory.from(command).orElseThrow();

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

        assertTrue(KeyMaterialLoaderFactory.from(command).isEmpty());
    }

    @Test
    void from_primus_returnsPrimusLoader() {
        var command = new DeactivateDidLogCommand();
        command.securosysPrimusKeyStoreLoader = mock(PrimusKeyStoreLoader.class);
        command.primusKeyAlias = "alias";
        command.primusKeyPassword = "secret";

        assertInstanceOf(PrimusKeyMaterialLoader.class, KeyMaterialLoaderFactory.from(command).orElseThrow());

        var popCommand = new CreateProofOfPossessionCommand();
        popCommand.securosysPrimusKeyStoreLoader = command.securosysPrimusKeyStoreLoader;
        popCommand.primusKeyAlias = "alias";
        popCommand.primusKeyPassword = "secret";

        assertInstanceOf(PrimusKeyMaterialLoader.class, KeyMaterialLoaderFactory.from(popCommand).orElseThrow());
    }

    @Test
    void from_popPem_returnsPemLoader() {
        var command = new CreateProofOfPossessionCommand();
        command.signingKeyPemFile = new File(TEST_DATA_PATH_PREFIX + "private.pem");

        var loader = KeyMaterialLoaderFactory.from(command).orElseThrow();

        assertInstanceOf(PemKeyMaterialLoader.class, loader);
        assertDoesNotThrow(() -> assertEquals("my-kid", loader.loadProofOfPossessionSigner("my-kid").getKid()));
    }
}
